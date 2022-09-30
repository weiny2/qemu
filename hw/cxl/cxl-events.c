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

void cxl_event_init(CXLDeviceState *cxlds)
{
    struct cxl_event_log *log;
    int i;

    for (i = 0; i < CXL_EVENT_TYPE_MAX; i++) {
        log = cxl_event_log(cxlds, i);
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
    return log->overflow;
}

void cxl_event_insert(struct cxl_event_log *log,
                      struct cxl_event_record_raw *event)
{
    CXLEvent *entry;

    if (cxl_event_count(log) >= CXL_TEST_EVENT_CNT_MAX) {
        /* FIXME set overflow data to be returned */
        log->overflow = true;
        return;
    }

    entry = g_new0(CXLEvent, 1);
    if (!entry) {
        error_report("Failed to allocate memory for event log entry");
        return;
    }

    /* Intentionally wrap the handles */
    entry->handle = log->next_handle++;

    /* FIXME timestamp these */
    memcpy(&entry->data, event, sizeof(*event));
    QSIMPLEQ_INSERT_TAIL(&log->events, entry, node);
}

void cxl_event_delete_head(struct cxl_event_log *log)
{
    CXLEvent *entry = cxl_event_get_head(log);

    QSIMPLEQ_REMOVE_HEAD(&log->events, node);
    g_free(entry);
}

static void cxl_event_irq_assert(PCIDevice *pdev)
{
    CXLType3Dev *ct3d = container_of(pdev, struct CXLType3Dev, parent_obj);
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
