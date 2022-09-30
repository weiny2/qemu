/*
 * CXL Event processing
 *
 * Copyright(C) 2022 Intel Corporation.
 *
 * This work is licensed under the terms of the GNU GPL, version 2. See the
 * COPYING file in the top-level directory.
 */

#include <stdint.h>

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qemu/typedefs.h"
#include "qemu/error-report.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "hw/cxl/cxl.h"
#include "hw/cxl/cxl_events.h"

/* Artificial limit on the number of events a log can hold */
#define CXL_TEST_EVENT_OVERFLOW 8

static void reset_overflow(struct cxl_event_log *log)
{
    log->overflow_err_count = 0;
    log->first_overflow_timestamp = 0;
    log->last_overflow_timestamp = 0;
}

void cxl_event_init(CXLDeviceState *cxlds, int start_msg_num)
{
    struct cxl_event_log *log;
    int i;

    for (i = 0; i < CXL_EVENT_TYPE_MAX; i++) {
        log = &cxlds->event_logs[i];
        log->next_handle = 1;
        log->overflow_err_count = 0;
        log->first_overflow_timestamp = 0;
        log->last_overflow_timestamp = 0;
        log->irq_enabled = false;
        log->irq_vec = start_msg_num++;
        qemu_mutex_init(&log->lock);
        QSIMPLEQ_INIT(&log->events);
    }

    /* Override -- Dynamic Capacity uses the same vector as info */
    cxlds->event_logs[CXL_EVENT_TYPE_DYNAMIC_CAP].irq_vec =
                      cxlds->event_logs[CXL_EVENT_TYPE_INFO].irq_vec;

}

static CXLEvent *cxl_event_get_head(struct cxl_event_log *log)
{
    return QSIMPLEQ_FIRST(&log->events);
}

static CXLEvent *cxl_event_get_next(CXLEvent *entry)
{
    return QSIMPLEQ_NEXT(entry, node);
}

static int cxl_event_count(struct cxl_event_log *log)
{
    CXLEvent *event;
    int rc = 0;

    QSIMPLEQ_FOREACH(event, &log->events, node) {
        rc++;
    }

    return rc;
}

static bool cxl_event_empty(struct cxl_event_log *log)
{
    return QSIMPLEQ_EMPTY(&log->events);
}

static void cxl_event_delete_head(CXLDeviceState *cxlds,
                                  enum cxl_event_log_type log_type,
                                  struct cxl_event_log *log)
{
    CXLEvent *entry = cxl_event_get_head(log);

    reset_overflow(log);
    QSIMPLEQ_REMOVE_HEAD(&log->events, node);
    if (cxl_event_empty(log)) {
        cxl_event_set_status(cxlds, log_type, false);
    }
    g_free(entry);
}

/*
 * return if an interrupt should be generated as a result of inserting this
 * event.
 */
bool cxl_event_insert(CXLDeviceState *cxlds,
                      enum cxl_event_log_type log_type,
                      struct cxl_event_record_raw *event)
{
    uint64_t time = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    struct cxl_event_log *log;
    CXLEvent *entry;

    if (log_type >= CXL_EVENT_TYPE_MAX) {
        return false;
    }

    log = &cxlds->event_logs[log_type];

    QEMU_LOCK_GUARD(&log->lock);

    if (cxl_event_count(log) >= CXL_TEST_EVENT_OVERFLOW) {
        if (log->overflow_err_count == 0) {
            log->first_overflow_timestamp = time;
        }
        log->overflow_err_count++;
        log->last_overflow_timestamp = time;
        return false;
    }

    entry = g_new0(CXLEvent, 1);
    if (!entry) {
        error_report("Failed to allocate memory for event log entry");
        return false;
    }

    memcpy(&entry->data, event, sizeof(*event));

    entry->data.hdr.handle = cpu_to_le16(log->next_handle);
    log->next_handle++;
    /* 0 handle is never valid */
    if (log->next_handle == 0) {
        log->next_handle++;
    }
    entry->data.hdr.timestamp = cpu_to_le64(time);

    QSIMPLEQ_INSERT_TAIL(&log->events, entry, node);
    cxl_event_set_status(cxlds, log_type, true);

    /* Count went from 0 to 1 */
    return cxl_event_count(log) == 1;
}

ret_code cxl_event_get_records(CXLDeviceState *cxlds,
                               struct cxl_get_event_payload *pl,
                               uint8_t log_type, int max_recs,
                               uint16_t *len)
{
    struct cxl_event_log *log;
    CXLEvent *entry;
    uint16_t nr;

    if (log_type >= CXL_EVENT_TYPE_MAX) {
        return CXL_MBOX_INVALID_INPUT;
    }

    log = &cxlds->event_logs[log_type];

    QEMU_LOCK_GUARD(&log->lock);

    entry = cxl_event_get_head(log);
    for (nr = 0; entry && nr < max_recs; nr++) {
        memcpy(&pl->records[nr], &entry->data, CXL_EVENT_RECORD_SIZE);
        entry = cxl_event_get_next(entry);
    }

    if (!cxl_event_empty(log)) {
        pl->flags |= CXL_GET_EVENT_FLAG_MORE_RECORDS;
    }

    if (log->overflow_err_count) {
        pl->flags |= CXL_GET_EVENT_FLAG_OVERFLOW;
        pl->overflow_err_count = cpu_to_le16(log->overflow_err_count);
        pl->first_overflow_timestamp = cpu_to_le64(log->first_overflow_timestamp);
        pl->last_overflow_timestamp = cpu_to_le64(log->last_overflow_timestamp);
    }

    pl->record_count = cpu_to_le16(nr);
    *len = CXL_EVENT_PAYLOAD_HDR_SIZE + (CXL_EVENT_RECORD_SIZE * nr);
    return CXL_MBOX_SUCCESS;
}

ret_code cxl_event_clear_records(CXLDeviceState *cxlds,
                                 struct cxl_clear_event_payload *pl)
{
    struct cxl_event_log *log;
    uint8_t log_type;
    CXLEvent *entry;
    int nr;

    log_type = pl->event_log;

    if (log_type >= CXL_EVENT_TYPE_MAX) {
        return CXL_MBOX_INVALID_INPUT;
    }

    log = &cxlds->event_logs[log_type];

    QEMU_LOCK_GUARD(&log->lock);
    /*
     * Must itterate the queue twice.
     * "The device shall verify the event record handles specified in the input
     * payload are in temporal order. If the device detects an older event
     * record that will not be cleared when Clear Event Records is executed,
     * the device shall return the Invalid Handle return code and shall not
     * clear any of the specified event records."
     *   -- CXL 3.0 8.2.9.2.3
     */
    entry = cxl_event_get_head(log);
    for (nr = 0; entry && nr < pl->nr_recs; nr++) {
        uint16_t handle = pl->handle[nr];

        /* NOTE: Both handles are little endian. */
        if (handle == 0 || entry->data.hdr.handle != handle) {
            return CXL_MBOX_INVALID_INPUT;
        }
        entry = cxl_event_get_next(entry);
    }

    entry = cxl_event_get_head(log);
    for (nr = 0; entry && nr < pl->nr_recs; nr++) {
        cxl_event_delete_head(cxlds, log_type, log);
        entry = cxl_event_get_head(log);
    }

    return CXL_MBOX_SUCCESS;
}

void cxl_event_irq_assert(CXLType3Dev *ct3d)
{
    CXLDeviceState *cxlds = &ct3d->cxl_dstate;
    PCIDevice *pdev = &ct3d->parent_obj;
    int i;

    for (i = 0; i < CXL_EVENT_TYPE_MAX; i++) {
        struct cxl_event_log *log = &cxlds->event_logs[i];

        if (!log->irq_enabled || cxl_event_empty(log)) {
            continue;
        }

        /*  Notifies interrupt, legacy IRQ is not supported */
        if (msix_enabled(pdev)) {
            msix_notify(pdev, log->irq_vec);
        } else if (msi_enabled(pdev)) {
            msi_notify(pdev, log->irq_vec);
        }
    }
}
