/*
 * QEMU CXL Events
 *
 * Copyright (c) 2022 Intel
 *
 * This work is licensed under the terms of the GNU GPL, version 2. See the
 * COPYING file in the top-level directory.
 */

#ifndef CXL_EVENTS_H
#define CXL_EVENTS_H

#include "qemu/uuid.h"

/*
 * CXL rev 3.0 section 8.2.9.2.2; Table 8-49
 *
 * Define these as the bit position for the event status register for ease of
 * setting the status.
 */
enum cxl_event_log_type {
    CXL_EVENT_TYPE_INFO          = 0,
    CXL_EVENT_TYPE_WARN          = 1,
    CXL_EVENT_TYPE_FAIL          = 2,
    CXL_EVENT_TYPE_FATAL         = 3,
    CXL_EVENT_TYPE_DYNAMIC_CAP   = 4,
    CXL_EVENT_TYPE_MAX
};

static inline const char *cxl_event_log_type_str(enum cxl_event_log_type type)
{
    switch (type) {
    case CXL_EVENT_TYPE_INFO:
        return "Informational";
    case CXL_EVENT_TYPE_WARN:
        return "Warning";
    case CXL_EVENT_TYPE_FAIL:
        return "Failure";
    case CXL_EVENT_TYPE_FATAL:
        return "Fatal";
    case CXL_EVENT_TYPE_DYNAMIC_CAP:
        return "Dynamic Capacity";
    default:
        break;
    }
    return "<unknown>";
}

/*
 * Common Event Record Format
 * CXL rev 3.0 section 8.2.9.2.1; Table 8-42
 */
#define CXL_EVENT_REC_HDR_RES_LEN 0xf
struct cxl_event_record_hdr {
    QemuUUID id;
    uint8_t length;
    uint8_t flags[3];
    uint16_t handle;
    uint16_t related_handle;
    uint64_t timestamp;
    uint8_t maint_op_class;
    uint8_t reserved[CXL_EVENT_REC_HDR_RES_LEN];
} QEMU_PACKED;

#define CXL_EVENT_RECORD_DATA_LENGTH 0x50
struct cxl_event_record_raw {
    struct cxl_event_record_hdr hdr;
    uint8_t data[CXL_EVENT_RECORD_DATA_LENGTH];
} QEMU_PACKED;

/*
 * Get Event Records output payload
 * CXL rev 3.0 section 8.2.9.2.2; Table 8-50
 *
 * Space given for 1 record
 */
#define CXL_GET_EVENT_FLAG_OVERFLOW     BIT(0)
#define CXL_GET_EVENT_FLAG_MORE_RECORDS BIT(1)
struct cxl_get_event_payload {
    uint8_t flags;
    uint8_t reserved1;
    uint16_t overflow_err_count;
    uint64_t first_overflow_timestamp;
    uint64_t last_overflow_timestamp;
    uint16_t record_count;
    uint8_t reserved2[0xa];
    struct cxl_event_record_raw record;
} QEMU_PACKED;

/*
 * Clear Event Records input payload
 * CXL rev 3.0 section 8.2.9.2.3; Table 8-51
 *
 * Space given for 1 record
 */
struct cxl_mbox_clear_event_payload {
    uint8_t event_log;      /* enum cxl_event_log_type */
    uint8_t clear_flags;
    uint8_t nr_recs;        /* 1 for this struct */
    uint8_t reserved[3];
    uint16_t handle;
};

/**
 * Event Interrupt Policy
 *
 * CXL rev 3.0 section 8.2.9.2.4; Table 8-52
 */
enum cxl_event_int_mode {
    CXL_INT_NONE     = 0x00,
    CXL_INT_MSI_MSIX = 0x01,
    CXL_INT_FW       = 0x02,
    CXL_INT_RES      = 0x03,
};
#define CXL_EVENT_INT_MODE_MASK 0x3
#define CXL_EVENT_INT_SETTING(vector) ((((uint8_t)vector & 0xf) << 4) | CXL_INT_MSI_MSIX)
struct cxl_event_interrupt_policy {
    uint8_t info_settings;
    uint8_t warn_settings;
    uint8_t failure_settings;
    uint8_t fatal_settings;
    uint8_t dyn_cap_settings;
} QEMU_PACKED;

/*
 * General Media Event Record
 * CXL rev 3.0 Section 8.2.9.2.1.1; Table 8-43
 */
#define CXL_EVENT_GEN_MED_COMP_ID_SIZE  0x10
#define CXL_EVENT_GEN_MED_RES_SIZE      0x2e
struct cxl_event_gen_media {
    struct cxl_event_record_hdr hdr;
    uint64_t phys_addr;
    uint8_t descriptor;
    uint8_t type;
    uint8_t transaction_type;
    uint8_t validity_flags[2];
    uint8_t channel;
    uint8_t rank;
    uint8_t device[3];
    uint8_t component_id[CXL_EVENT_GEN_MED_COMP_ID_SIZE];
    uint8_t reserved[CXL_EVENT_GEN_MED_RES_SIZE];
} QEMU_PACKED;

/*
 * DRAM Event Record - DER
 * CXL rev 3.0 section 8.2.9.2.1.2; Table 3-44
 */
#define CXL_EVENT_DER_CORRECTION_MASK_SIZE   0x20
#define CXL_EVENT_DER_RES_SIZE               0x17
struct cxl_event_dram {
    struct cxl_event_record_hdr hdr;
    uint64_t phys_addr;
    uint8_t descriptor;
    uint8_t type;
    uint8_t transaction_type;
    uint8_t validity_flags[2];
    uint8_t channel;
    uint8_t rank;
    uint8_t nibble_mask[3];
    uint8_t bank_group;
    uint8_t bank;
    uint8_t row[3];
    uint8_t column[2];
    uint8_t correction_mask[CXL_EVENT_DER_CORRECTION_MASK_SIZE];
    uint8_t reserved[CXL_EVENT_DER_RES_SIZE];
} QEMU_PACKED;

/*
 * Get Health Info Record
 * CXL rev 3.0 section 8.2.9.8.3.1; Table 8-100
 */
struct cxl_get_health_info {
    uint8_t health_status;
    uint8_t media_status;
    uint8_t add_status;
    uint8_t life_used;
    uint8_t device_temp[2];
    uint8_t dirty_shutdown_cnt[4];
    uint8_t cor_vol_err_cnt[4];
    uint8_t cor_per_err_cnt[4];
} QEMU_PACKED;

/*
 * Memory Module Event Record
 * CXL rev 3.0 section 8.2.9.2.1.3; Table 8-45
 */
#define CXL_EVENT_MEM_MOD_RES_SIZE  0x3d
struct cxl_event_mem_module {
    struct cxl_event_record_hdr hdr;
    uint8_t event_type;
    struct cxl_get_health_info info;
    uint8_t reserved[CXL_EVENT_MEM_MOD_RES_SIZE];
} QEMU_PACKED;

#endif /* CXL_EVENTS_H */
