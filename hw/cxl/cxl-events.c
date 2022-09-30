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

static void reset_overflow(struct cxl_event_log *log) {
    log->overflow_err_count = 0;
    log->first_overflow_timestamp = 0;
    log->last_overflow_timestamp = 0;
}

void cxl_event_init(CXLDeviceState *cxlds)
{
    struct cxl_event_log *log;
    int i;

    cxlds->event_status = 0;

    for (i = 0; i < CXL_EVENT_TYPE_MAX; i++) {
        log = cxl_event_log(cxlds, i);
        log->next_handle = 1;
        log->overflow_err_count = 0;
        log->first_overflow_timestamp = 0;
        log->last_overflow_timestamp = 0;
        log->irq_enabled = false;
        log->irq_vec = 0;
        QSIMPLEQ_INIT(&log->events);
    }
}

struct cxl_event_log *cxl_event_log(CXLDeviceState *cxlds,
                                    enum cxl_event_log_type log_type)
{
    if (log_type >= CXL_EVENT_TYPE_MAX) {
        error_report("Invalid log type: %d not supported", log_type);
        return NULL;
    }
    return &cxlds->event_logs[log_type];
}

CXLEvent *cxl_event_get_head(struct cxl_event_log *log)
{
    return QSIMPLEQ_FIRST(&log->events);
}

CXLEvent *cxl_event_get_next(CXLEvent *entry)
{
	return QSIMPLEQ_NEXT(entry, node);
}

int cxl_event_count(struct cxl_event_log *log)
{
    CXLEvent *event;
    int rc = 0;

    QSIMPLEQ_FOREACH(event, &log->events, node) {
        rc++;
    }

    return rc;
}

bool cxl_event_empty(struct cxl_event_log *log)
{
    return QSIMPLEQ_EMPTY(&log->events);
}

bool cxl_event_overflow(struct cxl_event_log *log)
{
    return log->overflow_err_count != 0;
}

void cxl_event_insert(CXLDeviceState *cxlds,
                      enum cxl_event_log_type log_type,
                      struct cxl_event_record_raw *event)
{
    struct cxl_event_log *log = cxl_event_log(cxlds, log_type);
    uint64_t time = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    CXLEvent *entry;

    if (cxl_event_count(log) >= CXL_TEST_EVENT_OVERFLOW) {
        if (log->overflow_err_count == 0) {
            log->first_overflow_timestamp = time;
        }
        log->overflow_err_count++;
        log->last_overflow_timestamp = time;
        return;
    }

    entry = g_new0(CXLEvent, 1);
    if (!entry) {
        error_report("Failed to allocate memory for event log entry");
        return;
    }

    memset(entry, 0, sizeof(*entry));
    memcpy(&entry->data, event, sizeof(*event));

    /* Intentionally wrap the handles */
    entry->data.hdr.handle = cpu_to_le16(log->next_handle);
    log->next_handle++;
    /* 0 handle is never valid */
    if (log->next_handle == 0)
        log->next_handle++;
    entry->data.hdr.timestamp = cpu_to_le64(time);

    QSIMPLEQ_INSERT_TAIL(&log->events, entry, node);
    cxl_event_set_status(cxlds, log_type, true);
}

void cxl_event_delete_head(CXLDeviceState *cxlds,
                           enum cxl_event_log_type log_type,
			   struct cxl_event_log *log)
{
    CXLEvent *entry = cxl_event_get_head(log);

    reset_overflow(log);
    QSIMPLEQ_REMOVE_HEAD(&log->events, node);
    if (cxl_event_empty(log))
        cxl_event_set_status(cxlds, log_type, false);
    g_free(entry);
}

void cxl_event_irq_assert(CXLType3Dev *ct3d)
{
    PCIDevice *pdev = &ct3d->parent_obj;
    CXLDeviceState *cxlds = &ct3d->cxl_dstate;
    int i;

    for (i = 0; i < CXL_EVENT_TYPE_MAX; i++) {
        struct cxl_event_log *log;

        log = cxl_event_log(cxlds, i);
        if (!log || !log->irq_enabled || cxl_event_empty(log)) {
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
