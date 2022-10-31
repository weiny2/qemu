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
#include "sysemu/sysemu.h"
#include "monitor/monitor.h"
#include "qemu/bswap.h"
#include "qemu/typedefs.h"
#include "qemu/error-report.h"
#include "qapi/qmp/qdict.h"
#include "hw/pci/pci.h"
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

#define CXL_EVENT_RECORD_FLAG_PERMANENT         BIT(2)
#define CXL_EVENT_RECORD_FLAG_MAINT_NEEDED      BIT(3)
#define CXL_EVENT_RECORD_FLAG_PERF_DEGRADED     BIT(4)
#define CXL_EVENT_RECORD_FLAG_HW_REPLACE        BIT(5)

struct cxl_event_record_raw maint_needed = {
    .hdr = {
        .id.data = UUID(0xDEADBEEF, 0xCAFE, 0xBABE,
                        0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0xa5, 0x5a, 0xa5),
        .length = sizeof(struct cxl_event_record_raw),
        .flags[0] = CXL_EVENT_RECORD_FLAG_MAINT_NEEDED,
        /* .handle = Set dynamically */
        .related_handle = const_le16(0xa5b6),
    },
    .data = { 0xDE, 0xAD, 0xBE, 0xEF },
};

struct cxl_event_record_raw hardware_replace = {
    .hdr = {
        .id.data = UUID(0xBABECAFE, 0xBEEF, 0xDEAD,
                        0xa5, 0x5a, 0xa5, 0x5a, 0xa5, 0xa5, 0x5a, 0xa5),
        .length = sizeof(struct cxl_event_record_raw),
        .flags[0] = CXL_EVENT_RECORD_FLAG_HW_REPLACE,
        /* .handle = Set dynamically */
        .related_handle = const_le16(0xb6a5),
    },
    .data = { 0xDE, 0xAD, 0xBE, 0xEF },
};

#define CXL_GMER_EVT_DESC_UNCORECTABLE_EVENT            BIT(0)
#define CXL_GMER_EVT_DESC_THRESHOLD_EVENT               BIT(1)
#define CXL_GMER_EVT_DESC_POISON_LIST_OVERFLOW          BIT(2)

#define CXL_GMER_MEM_EVT_TYPE_ECC_ERROR                 0x00
#define CXL_GMER_MEM_EVT_TYPE_INV_ADDR                  0x01
#define CXL_GMER_MEM_EVT_TYPE_DATA_PATH_ERROR           0x02

#define CXL_GMER_TRANS_UNKNOWN                          0x00
#define CXL_GMER_TRANS_HOST_READ                        0x01
#define CXL_GMER_TRANS_HOST_WRITE                       0x02
#define CXL_GMER_TRANS_HOST_SCAN_MEDIA                  0x03
#define CXL_GMER_TRANS_HOST_INJECT_POISON               0x04
#define CXL_GMER_TRANS_INTERNAL_MEDIA_SCRUB             0x05
#define CXL_GMER_TRANS_INTERNAL_MEDIA_MANAGEMENT        0x06

#define CXL_GMER_VALID_CHANNEL                          BIT(0)
#define CXL_GMER_VALID_RANK                             BIT(1)
#define CXL_GMER_VALID_DEVICE                           BIT(2)
#define CXL_GMER_VALID_COMPONENT                        BIT(3)

struct cxl_event_gen_media gen_media = {
    .hdr = {
        .id.data = UUID(0xfbcd0a77, 0xc260, 0x417f,
                        0x85, 0xa9, 0x08, 0x8b, 0x16, 0x21, 0xeb, 0xa6),
        .length = sizeof(struct cxl_event_gen_media),
        .flags[0] = CXL_EVENT_RECORD_FLAG_PERMANENT,
        /* .handle = Set dynamically */
        .related_handle = const_le16(0),
    },
    .phys_addr = const_le64(0x2000),
    .descriptor = CXL_GMER_EVT_DESC_UNCORECTABLE_EVENT,
    .type = CXL_GMER_MEM_EVT_TYPE_DATA_PATH_ERROR,
    .transaction_type = CXL_GMER_TRANS_HOST_WRITE,
    .validity_flags = { CXL_GMER_VALID_CHANNEL |
                        CXL_GMER_VALID_RANK, 0 },
    .channel = 1,
    .rank = 30
};

#define CXL_DER_VALID_CHANNEL                           BIT(0)
#define CXL_DER_VALID_RANK                              BIT(1)
#define CXL_DER_VALID_NIBBLE                            BIT(2)
#define CXL_DER_VALID_BANK_GROUP                        BIT(3)
#define CXL_DER_VALID_BANK                              BIT(4)
#define CXL_DER_VALID_ROW                               BIT(5)
#define CXL_DER_VALID_COLUMN                            BIT(6)
#define CXL_DER_VALID_CORRECTION_MASK                   BIT(7)

struct cxl_event_dram dram = {
    .hdr = {
        .id.data = UUID(0x601dcbb3, 0x9c06, 0x4eab,
                        0xb8, 0xaf, 0x4e, 0x9b, 0xfb, 0x5c, 0x96, 0x24),
        .length = sizeof(struct cxl_event_dram),
        .flags[0] = CXL_EVENT_RECORD_FLAG_PERF_DEGRADED,
        /* .handle = Set dynamically */
        .related_handle = const_le16(0),
    },
    .phys_addr = const_le64(0x8000),
    .descriptor = CXL_GMER_EVT_DESC_THRESHOLD_EVENT,
    .type = CXL_GMER_MEM_EVT_TYPE_INV_ADDR,
    .transaction_type = CXL_GMER_TRANS_INTERNAL_MEDIA_SCRUB,
    .validity_flags = { CXL_DER_VALID_CHANNEL |
                        CXL_DER_VALID_BANK_GROUP |
                        CXL_DER_VALID_BANK |
                        CXL_DER_VALID_COLUMN, 0 },
    .channel = 1,
    .bank_group = 5,
    .bank = 2,
    .column = { 0xDE, 0xAD},
};

#define CXL_MMER_HEALTH_STATUS_CHANGE           0x00
#define CXL_MMER_MEDIA_STATUS_CHANGE            0x01
#define CXL_MMER_LIFE_USED_CHANGE               0x02
#define CXL_MMER_TEMP_CHANGE                    0x03
#define CXL_MMER_DATA_PATH_ERROR                0x04
#define CXL_MMER_LAS_ERROR                      0x05

#define CXL_DHI_HS_MAINTENANCE_NEEDED           BIT(0)
#define CXL_DHI_HS_PERFORMANCE_DEGRADED         BIT(1)
#define CXL_DHI_HS_HW_REPLACEMENT_NEEDED        BIT(2)

#define CXL_DHI_MS_NORMAL                                    0x00
#define CXL_DHI_MS_NOT_READY                                 0x01
#define CXL_DHI_MS_WRITE_PERSISTENCY_LOST                    0x02
#define CXL_DHI_MS_ALL_DATA_LOST                             0x03
#define CXL_DHI_MS_WRITE_PERSISTENCY_LOSS_EVENT_POWER_LOSS   0x04
#define CXL_DHI_MS_WRITE_PERSISTENCY_LOSS_EVENT_SHUTDOWN     0x05
#define CXL_DHI_MS_WRITE_PERSISTENCY_LOSS_IMMINENT           0x06
#define CXL_DHI_MS_WRITE_ALL_DATA_LOSS_EVENT_POWER_LOSS      0x07
#define CXL_DHI_MS_WRITE_ALL_DATA_LOSS_EVENT_SHUTDOWN        0x08
#define CXL_DHI_MS_WRITE_ALL_DATA_LOSS_IMMINENT              0x09

#define CXL_DHI_AS_NORMAL               0x0
#define CXL_DHI_AS_WARNING              0x1
#define CXL_DHI_AS_CRITICAL             0x2

#define CXL_DHI_AS_LIFE_USED(as)        (as & 0x3)
#define CXL_DHI_AS_DEV_TEMP(as)         ((as & 0xC) >> 2)
#define CXL_DHI_AS_COR_VOL_ERR_CNT(as)  ((as & 0x10) >> 4)
#define CXL_DHI_AS_COR_PER_ERR_CNT(as)  ((as & 0x20) >> 5)

struct cxl_event_mem_module mem_module = {
    .hdr = {
        .id.data = UUID(0xfe927475, 0xdd59, 0x4339,
                        0xa5, 0x86, 0x79, 0xba, 0xb1, 0x13, 0xb7, 0x74),
        .length = sizeof(struct cxl_event_mem_module),
        /* .handle = Set dynamically */
        .related_handle = const_le16(0),
    },
    .event_type = CXL_MMER_TEMP_CHANGE,
    .info = {
        .health_status = CXL_DHI_HS_PERFORMANCE_DEGRADED,
        .media_status = CXL_DHI_MS_ALL_DATA_LOST,
        .add_status = (CXL_DHI_AS_CRITICAL << 2) |
                       (CXL_DHI_AS_WARNING << 4) |
                       (CXL_DHI_AS_WARNING << 5),
        .device_temp = { 0xDE, 0xAD},
        .dirty_shutdown_cnt = { 0xde, 0xad, 0xbe, 0xef },
        .cor_vol_err_cnt = { 0xde, 0xad, 0xbe, 0xef },
        .cor_per_err_cnt = { 0xde, 0xad, 0xbe, 0xef },
    }
};

void cxl_mock_add_event_logs(CXLDeviceState *cxlds)
{
    cxl_event_insert(cxlds, CXL_EVENT_TYPE_INFO, &maint_needed);
    cxl_event_insert(cxlds, CXL_EVENT_TYPE_INFO, (struct cxl_event_record_raw *)&gen_media);
    cxl_event_insert(cxlds, CXL_EVENT_TYPE_INFO, (struct cxl_event_record_raw *)&mem_module);

    cxl_event_insert(cxlds, CXL_EVENT_TYPE_FAIL, &maint_needed);
    cxl_event_insert(cxlds, CXL_EVENT_TYPE_FAIL, &hardware_replace);
    cxl_event_insert(cxlds, CXL_EVENT_TYPE_FAIL, (struct cxl_event_record_raw *)&dram);
    cxl_event_insert(cxlds, CXL_EVENT_TYPE_FAIL, (struct cxl_event_record_raw *)&gen_media);
    cxl_event_insert(cxlds, CXL_EVENT_TYPE_FAIL, (struct cxl_event_record_raw *)&mem_module);
    cxl_event_insert(cxlds, CXL_EVENT_TYPE_FAIL, &hardware_replace);
    cxl_event_insert(cxlds, CXL_EVENT_TYPE_FAIL, (struct cxl_event_record_raw *)&dram);

    cxl_event_insert(cxlds, CXL_EVENT_TYPE_FATAL, &hardware_replace);
    cxl_event_insert(cxlds, CXL_EVENT_TYPE_FATAL, (struct cxl_event_record_raw *)&dram);
}

static int do_cxl_event_inject(Monitor *mon, const QDict *qdict)
{
    const char *id = qdict_get_str(qdict, "id");
    CXLType3Dev *ct3d;
    PCIDevice *pdev;
    int ret;

    ret = pci_qdev_find_device(id, &pdev);
    if (ret < 0) {
        monitor_printf(mon,
                       "id or cxl device path is invalid or device not "
                       "found. %s\n", id);
        return ret;
    }

    ct3d = container_of(pdev, struct CXLType3Dev, parent_obj);
    cxl_mock_add_event_logs(&ct3d->cxl_dstate);

    cxl_event_irq_assert(ct3d);
    return 0;
}

void hmp_cxl_event_inject(Monitor *mon, const QDict *qdict)
{
    const char *id = qdict_get_str(qdict, "id");

    if (do_cxl_event_inject(mon, qdict) < 0) {
        return;
    }

    monitor_printf(mon, "OK id: %s\n", id);
}
