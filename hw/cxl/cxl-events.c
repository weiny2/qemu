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
        log->next_handle = 0;
        log->overflow_err_count = 0;
        log->first_overflow_timestamp = 0;
        log->last_overflow_timestamp = 0;
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

    if (cxl_event_count(log) >= CXL_TEST_EVENT_CNT_MAX) {
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

    /* Intentionally wrap the handles */
    entry->data.hdr.handle = cpu_to_le16(log->next_handle);
    log->next_handle++;
    entry->data.hdr.timestamp = cpu_to_le64(time);

    memcpy(&entry->data, event, sizeof(*event));
    cxl_event_set_status(cxlds, log_type, true);
    QSIMPLEQ_INSERT_TAIL(&log->events, entry, node);
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
