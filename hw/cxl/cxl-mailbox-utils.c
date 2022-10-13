/*
 * CXL Utility library for mailbox interface
 *
 * Copyright(C) 2020 Intel Corporation.
 *
 * This work is licensed under the terms of the GNU GPL, version 2. See the
 * COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "hw/cxl/cxl.h"
#include "hw/pci/pci.h"
#include "hw/pci-bridge/cxl_upstream_port.h"
#include "qemu/cutils.h"
#include "qemu/log.h"
#include "qemu/uuid.h"

#define CXL_CAPACITY_MULTIPLIER   0x10000000 /* SZ_256M */

/*
 * How to add a new command, example. The command set FOO, with cmd BAR.
 *  1. Add the command set and cmd to the enum.
 *     FOO    = 0x7f,
 *          #define BAR 0
 *  2. Implement the handler
 *    static ret_code cmd_foo_bar(struct cxl_cmd *cmd,
 *                                  CXLDeviceState *cxl_dstate, uint16_t *len)
 *  3. Add the command to the cxl_cmd_set[][]
 *    [FOO][BAR] = { "FOO_BAR", cmd_foo_bar, x, y },
 *  4. Implement your handler
 *     define_mailbox_handler(FOO_BAR) { ... return CXL_MBOX_SUCCESS; }
 *
 *
 *  Writing the handler:
 *    The handler will provide the &struct cxl_cmd, the &CXLDeviceState, and the
 *    in/out length of the payload. The handler is responsible for consuming the
 *    payload from cmd->payload and operating upon it as necessary. It must then
 *    fill the output data into cmd->payload (overwriting what was there),
 *    setting the length, and returning a valid return code.
 *
 *  XXX: The handler need not worry about endianess. The payload is read out of
 *  a register interface that already deals with it.
 */

enum {
    INFOSTAT    = 0x00,
        #define IS_IDENTIFY   0x1
        #define BACKGROUND_OPERATION_STATUS    0x2
        #define GET_RESPONSE_MESSAGE_LIMIT     0x3
        #define SET_RESPONSE_MESSAGE_LIMIT     0x4
    EVENTS      = 0x01,
        #define GET_RECORDS   0x0
        #define CLEAR_RECORDS   0x1
        #define GET_INTERRUPT_POLICY   0x2
        #define SET_INTERRUPT_POLICY   0x3
    FIRMWARE_UPDATE = 0x02,
        #define GET_INFO      0x0
    TIMESTAMP   = 0x03,
        #define GET           0x0
        #define SET           0x1
    LOGS        = 0x04,
        #define GET_SUPPORTED 0x0
        #define GET_LOG       0x1
    IDENTIFY    = 0x40,
        #define MEMORY_DEVICE 0x0
    CCLS        = 0x41,
        #define GET_PARTITION_INFO     0x0
        #define GET_LSA       0x2
        #define SET_LSA       0x3
    MEDIA_AND_POISON = 0x43,
        #define GET_POISON_LIST        0x0
    PHYSICAL_SWITCH = 0x51
        #define IDENTIFY_SWITCH_DEVICE      0x0
};

#define DEFINE_MAILBOX_HANDLER_ZEROED(name, size)                         \
    uint16_t __zero##name = size;                                         \
    static ret_code cmd_##name(struct cxl_cmd *cmd,                       \
                               CXLDeviceState *cxl_dstate, uint16_t *len) \
    {                                                                     \
        *len = __zero##name;                                              \
        memset(cmd->payload, 0, *len);                                    \
        return CXL_MBOX_SUCCESS;                                          \
    }
#define DEFINE_MAILBOX_HANDLER_NOP(name)                                  \
    static ret_code cmd_##name(struct cxl_cmd *cmd,                       \
                               CXLDeviceState *cxl_dstate, uint16_t *len) \
    {                                                                     \
        return CXL_MBOX_SUCCESS;                                          \
    }

DEFINE_MAILBOX_HANDLER_ZEROED(events_get_records, 0x20);
DEFINE_MAILBOX_HANDLER_NOP(events_clear_records);
DEFINE_MAILBOX_HANDLER_ZEROED(events_get_interrupt_policy, 4);
DEFINE_MAILBOX_HANDLER_NOP(events_set_interrupt_policy);

static void find_cxl_usp(PCIBus *b, PCIDevice *d, void *opaque)
{
    PCIDevice **found_dev = opaque;

    if (object_dynamic_cast(OBJECT(d), TYPE_CXL_USP)) {
        *found_dev = d;
    }
}

static PCIDevice *switch_cci_to_usp(PCIDevice *cci_pci_dev)
{
    /*
     * Assumptions in here that this port is on same bus as
     * a switch upstream port.  Otherwise we need to more clever
     * about CCI to switch connectivity.
     */
    PCIBus *pci_bus = pci_get_bus(cci_pci_dev);
    PCIDevice *pci_dev = NULL;

    pci_for_each_device_under_bus(pci_bus, find_cxl_usp, &pci_dev);

    return pci_dev;
}

/* CXL r3 8.2.9.1.1 */
static ret_code cmd_infostat_identify(struct cxl_cmd *cmd,
                                      CXLDeviceState *cxl_dstate,
                                      uint16_t *len)
{
    /*
     * Assumptions in here that this port is on same bus as
     * a switch upstream port.  Otherwise we need to more clever
     * about CCI to switch connectivity.
     */

    /* Find a Peer Upstream Port */
    PCIDevice *cci_pci_dev = PCI_DEVICE(container_of(cxl_dstate,
                                                     struct CSWMBCCIDev,
                                                     cxl_dstate));
    PCIDevice *pci_dev = switch_cci_to_usp(cci_pci_dev);
    struct {
        uint16_t pcie_vid;
        uint16_t pcie_did;
        uint16_t pcie_subsys_vid;
        uint16_t pcie_subsys_id;
        uint64_t sn;
        uint8_t max_message_size;
        uint8_t component_type;
    } QEMU_PACKED *is_identify;
    QEMU_BUILD_BUG_ON(sizeof(*is_identify) != 18);
    is_identify = (void *)cmd->payload;
    memset(is_identify, 0, sizeof(*is_identify));
    if (pci_dev) {
        CXLUpstreamPort *port = CXL_USP(pci_dev);
        /*
         * Messy question - which IDs?  Those of the CCI Function, or those of
         * the USP?
         */
        is_identify->pcie_vid = pci_get_word(&pci_dev->config[PCI_VENDOR_ID]);
        is_identify->pcie_did = pci_get_word(&pci_dev->config[PCI_DEVICE_ID]);
        is_identify->pcie_subsys_vid = 0; /* Not defined for a USP */
        is_identify->pcie_subsys_id = 0; /* Not defined for a USP */

        is_identify->sn = port->sn;
        is_identify->max_message_size = CXL_MAILBOX_PAYLOAD_SHIFT;
        is_identify->component_type = 0; /* Switch */
    }
    *len = sizeof(*is_identify);
    return CXL_MBOX_SUCCESS;
}

static void cxl_count_dsp(PCIBus *b, PCIDevice *d, void *private)
{
    uint16_t *count = private;
    if (object_dynamic_cast(OBJECT(d), TYPE_CXL_DSP)) {
        *count = *count + 1;
    }
}

static void cxl_set_dsp_active_bm(PCIBus *b, PCIDevice *d,
                                  void *private)
{
    uint8_t *bm = private;
    if (object_dynamic_cast(OBJECT(d), TYPE_CXL_DSP)) {
        uint8_t port = PCIE_PORT(d)->port;
        bm[port / 8] |= 1 << (port % 8);
    }
}

/* CXL r3 8.2.9.1.1 */
static ret_code cmd_identify_switch_device(struct cxl_cmd *cmd,
                                           CXLDeviceState *cxl_dstate,
                                           uint16_t *len)
{
    /* Find a Peer Upstream Port */
    PCIDevice *cci_pci_dev = PCI_DEVICE(container_of(cxl_dstate,
                                                     struct CSWMBCCIDev,
                                                     cxl_dstate));

    struct {
        uint8_t ingress_port_id;
        uint8_t rsvd;
        uint8_t num_physical_ports;
        uint8_t num_vcs;
        uint8_t active_port_bitmap[0x20];
        uint8_t active_vcs_bitmap[0x20];
        uint16_t total_vppbs;
        uint16_t bound_vppbs;
        uint8_t num_hdm_decoders_per_usp;
    } QEMU_PACKED *identify_sw_dev_rsp;
    QEMU_BUILD_BUG_ON(sizeof(*identify_sw_dev_rsp) != 0x49);
    PCIDevice *pci_dev = switch_cci_to_usp(cci_pci_dev);

    identify_sw_dev_rsp = (void *)cmd->payload;
    memset(identify_sw_dev_rsp, 0, sizeof(*identify_sw_dev_rsp));
    if (pci_dev) {
        PCIBus *pci_bus = pci_bridge_get_sec_bus(PCI_BRIDGE(pci_dev));
        uint16_t num_dsp = 0;

        pci_for_each_device_under_bus(pci_bus, cxl_count_dsp, &num_dsp);
        identify_sw_dev_rsp->ingress_port_id = PCIE_PORT(pci_dev)->port;
        identify_sw_dev_rsp->num_physical_ports = 1 + num_dsp;
         /* Will be a while before we get more complex and need more VCS */
        identify_sw_dev_rsp->num_vcs = 1;
        pci_for_each_device_under_bus(pci_bus, cxl_set_dsp_active_bm,
                                      identify_sw_dev_rsp->active_port_bitmap);
        
        identify_sw_dev_rsp->active_vcs_bitmap[0] = 0x1;
        identify_sw_dev_rsp->total_vppbs = num_dsp; /* Fixed binding */
        identify_sw_dev_rsp->bound_vppbs = num_dsp;
         /* Only one HDM decoder implemented so far */
        identify_sw_dev_rsp->num_hdm_decoders_per_usp = 1;
    }
    *len = sizeof(*identify_sw_dev_rsp);
    return CXL_MBOX_SUCCESS;
}

/* CXL r3.0 8.2.9.1.2 */
static ret_code cmd_infostat_bg_op_sts(struct cxl_cmd *cmd,
                                       CXLDeviceState *cxl_dstate,
                                       uint16_t *len)
{
    struct {
        uint8_t status;
        uint8_t rsvd;
        uint16_t opcode;
        uint16_t returncode;
        uint16_t vendor_ext_status;
    } QEMU_PACKED *bg_op_status;
    QEMU_BUILD_BUG_ON(sizeof(*bg_op_status) != 8);

    bg_op_status = (void *)cmd->payload;
    memset(bg_op_status, 0, sizeof(*bg_op_status));
    /* No support yet for background operations so status all 0 */
    *len = sizeof(*bg_op_status);
    return CXL_MBOX_SUCCESS;
}

/* 8.2.9.2.1 */
static ret_code cmd_firmware_update_get_info(struct cxl_cmd *cmd,
                                             CXLDeviceState *cxl_dstate,
                                             uint16_t *len)
{
    struct {
        uint8_t slots_supported;
        uint8_t slot_info;
        uint8_t caps;
        uint8_t rsvd[0xd];
        char fw_rev1[0x10];
        char fw_rev2[0x10];
        char fw_rev3[0x10];
        char fw_rev4[0x10];
    } QEMU_PACKED *fw_info;
    QEMU_BUILD_BUG_ON(sizeof(*fw_info) != 0x50);

    if (cxl_dstate->mem_size < CXL_CAPACITY_MULTIPLIER) {
        return CXL_MBOX_INTERNAL_ERROR;
    }

    fw_info = (void *)cmd->payload;
    memset(fw_info, 0, sizeof(*fw_info));

    fw_info->slots_supported = 2;
    fw_info->slot_info = BIT(0) | BIT(3);
    fw_info->caps = 0;
    pstrcpy(fw_info->fw_rev1, sizeof(fw_info->fw_rev1), "BWFW VERSION 0");

    *len = sizeof(*fw_info);
    return CXL_MBOX_SUCCESS;
}

/* 8.2.9.3.1 */
static ret_code cmd_timestamp_get(struct cxl_cmd *cmd,
                                  CXLDeviceState *cxl_dstate,
                                  uint16_t *len)
{
    uint64_t time, delta;
    uint64_t final_time = 0;

    if (cxl_dstate->timestamp.set) {
        /* First find the delta from the last time the host set the time. */
        time = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        delta = time - cxl_dstate->timestamp.last_set;
        final_time = cxl_dstate->timestamp.host_set + delta;
    }

    /* Then adjust the actual time */
    stq_le_p(cmd->payload, final_time);
    *len = 8;

    return CXL_MBOX_SUCCESS;
}

/* 8.2.9.3.2 */
static ret_code cmd_timestamp_set(struct cxl_cmd *cmd,
                                  CXLDeviceState *cxl_dstate,
                                  uint16_t *len)
{
    cxl_dstate->timestamp.set = true;
    cxl_dstate->timestamp.last_set = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    cxl_dstate->timestamp.host_set = le64_to_cpu(*(uint64_t *)cmd->payload);

    *len = 0;
    return CXL_MBOX_SUCCESS;
}

/* CXL 3.0 8.2.9.5.2.1 Command Effects Log (CEL) */
static QemuUUID cel_uuid = {
        .data = UUID(0x0da9c0b5, 0xbf41, 0x4b78, 0x8f, 0x79,
                     0x96, 0xb1, 0x62, 0x3b, 0x3f, 0x17)
};

/* 8.2.9.4.1 */
static ret_code cmd_logs_get_supported(struct cxl_cmd *cmd,
                                       CXLDeviceState *cxl_dstate,
                                       uint16_t *len)
{
    struct {
        uint16_t entries;
        uint8_t rsvd[6];
        struct {
            QemuUUID uuid;
            uint32_t size;
        } log_entries[1];
    } QEMU_PACKED *supported_logs = (void *)cmd->payload;
    QEMU_BUILD_BUG_ON(sizeof(*supported_logs) != 0x1c);

    supported_logs->entries = 1;
    supported_logs->log_entries[0].uuid = cel_uuid;
    supported_logs->log_entries[0].size = 4 * cxl_dstate->cel_size;

    *len = sizeof(*supported_logs);
    return CXL_MBOX_SUCCESS;
}

/* 8.2.9.4.2 */
static ret_code cmd_logs_get_log(struct cxl_cmd *cmd,
                                 CXLDeviceState *cxl_dstate,
                                 uint16_t *len)
{
    struct {
        QemuUUID uuid;
        uint32_t offset;
        uint32_t length;
    } QEMU_PACKED QEMU_ALIGNED(16) *get_log = (void *)cmd->payload;

    /*
     * 8.2.9.4.2
     *   The device shall return Invalid Parameter if the Offset or Length
     *   fields attempt to access beyond the size of the log as reported by Get
     *   Supported Logs.
     *
     * XXX: Spec is wrong, "Invalid Parameter" isn't a thing.
     * XXX: Spec doesn't address incorrect UUID incorrectness.
     *
     * The CEL buffer is large enough to fit all commands in the emulation, so
     * the only possible failure would be if the mailbox itself isn't big
     * enough.
     */
    if (get_log->offset + get_log->length > cxl_dstate->payload_size) {
        return CXL_MBOX_INVALID_INPUT;
    }

    if (!qemu_uuid_is_equal(&get_log->uuid, &cel_uuid)) {
        return CXL_MBOX_UNSUPPORTED;
    }

    /* Store off everything to local variables so we can wipe out the payload */
    *len = get_log->length;

    memmove(cmd->payload, cxl_dstate->cel_log + get_log->offset,
           get_log->length);

    return CXL_MBOX_SUCCESS;
}

/* 8.2.9.5.1.1 */
static ret_code cmd_identify_memory_device(struct cxl_cmd *cmd,
                                           CXLDeviceState *cxl_dstate,
                                           uint16_t *len)
{
    struct {
        char fw_revision[0x10];
        uint64_t total_capacity;
        uint64_t volatile_capacity;
        uint64_t persistent_capacity;
        uint64_t partition_align;
        uint16_t info_event_log_size;
        uint16_t warning_event_log_size;
        uint16_t failure_event_log_size;
        uint16_t fatal_event_log_size;
        uint32_t lsa_size;
        uint8_t poison_list_max_mer[3];
        uint16_t inject_poison_limit;
        uint8_t poison_caps;
        uint8_t qos_telemetry_caps;
    } QEMU_PACKED *id;
    QEMU_BUILD_BUG_ON(sizeof(*id) != 0x43);

    CXLType3Dev *ct3d = container_of(cxl_dstate, CXLType3Dev, cxl_dstate);
    CXLType3Class *cvc = CXL_TYPE3_GET_CLASS(ct3d);

    if ((!QEMU_IS_ALIGNED(cxl_dstate->vmem_size, CXL_CAPACITY_MULTIPLIER)) ||
        (!QEMU_IS_ALIGNED(cxl_dstate->pmem_size, CXL_CAPACITY_MULTIPLIER))) {
        return CXL_MBOX_INTERNAL_ERROR;
    }

    id = (void *)cmd->payload;
    memset(id, 0, sizeof(*id));

    snprintf(id->fw_revision, 0x10, "BWFW VERSION %02d", 0);

    id->total_capacity = cxl_dstate->mem_size / CXL_CAPACITY_MULTIPLIER;
    id->persistent_capacity = cxl_dstate->pmem_size / CXL_CAPACITY_MULTIPLIER;
    id->volatile_capacity = cxl_dstate->vmem_size / CXL_CAPACITY_MULTIPLIER;
    id->lsa_size = cvc->get_lsa_size(ct3d);
    id->poison_list_max_mer[1] = 0x1; /* 256 poison records */

    *len = sizeof(*id);
    return CXL_MBOX_SUCCESS;
}

static ret_code cmd_ccls_get_partition_info(struct cxl_cmd *cmd,
                                           CXLDeviceState *cxl_dstate,
                                           uint16_t *len)
{
    struct {
        uint64_t active_vmem;
        uint64_t active_pmem;
        uint64_t next_vmem;
        uint64_t next_pmem;
    } QEMU_PACKED *part_info = (void *)cmd->payload;
    QEMU_BUILD_BUG_ON(sizeof(*part_info) != 0x20);

    if ((!QEMU_IS_ALIGNED(cxl_dstate->vmem_size, CXL_CAPACITY_MULTIPLIER)) ||
        (!QEMU_IS_ALIGNED(cxl_dstate->pmem_size, CXL_CAPACITY_MULTIPLIER))) {
        return CXL_MBOX_INTERNAL_ERROR;
    }

    part_info->active_vmem = cxl_dstate->vmem_size / CXL_CAPACITY_MULTIPLIER;
    part_info->next_vmem = 0;
    part_info->active_pmem = cxl_dstate->pmem_size / CXL_CAPACITY_MULTIPLIER;
    part_info->next_pmem = 0;

    *len = sizeof(*part_info);
    return CXL_MBOX_SUCCESS;
}

static ret_code cmd_ccls_get_lsa(struct cxl_cmd *cmd,
                                 CXLDeviceState *cxl_dstate,
                                 uint16_t *len)
{
    struct {
        uint32_t offset;
        uint32_t length;
    } QEMU_PACKED *get_lsa;
    CXLType3Dev *ct3d = container_of(cxl_dstate, CXLType3Dev, cxl_dstate);
    CXLType3Class *cvc = CXL_TYPE3_GET_CLASS(ct3d);
    uint32_t offset, length;

    get_lsa = (void *)cmd->payload;
    offset = get_lsa->offset;
    length = get_lsa->length;

    if (offset + length > cvc->get_lsa_size(ct3d)) {
        *len = 0;
        return CXL_MBOX_INVALID_INPUT;
    }

    *len = cvc->get_lsa(ct3d, get_lsa, length, offset);
    return CXL_MBOX_SUCCESS;
}

static ret_code cmd_ccls_set_lsa(struct cxl_cmd *cmd,
                                 CXLDeviceState *cxl_dstate,
                                 uint16_t *len)
{
    struct set_lsa_pl {
        uint32_t offset;
        uint32_t rsvd;
        uint8_t data[];
    } QEMU_PACKED;
    struct set_lsa_pl *set_lsa_payload = (void *)cmd->payload;
    CXLType3Dev *ct3d = container_of(cxl_dstate, CXLType3Dev, cxl_dstate);
    CXLType3Class *cvc = CXL_TYPE3_GET_CLASS(ct3d);
    const size_t hdr_len = offsetof(struct set_lsa_pl, data);
    uint16_t plen = *len;

    *len = 0;
    if (!plen) {
        return CXL_MBOX_SUCCESS;
    }

    if (set_lsa_payload->offset + plen > cvc->get_lsa_size(ct3d) + hdr_len) {
        return CXL_MBOX_INVALID_INPUT;
    }
    plen -= hdr_len;

    cvc->set_lsa(ct3d, set_lsa_payload->data, plen, set_lsa_payload->offset);
    return CXL_MBOX_SUCCESS;
}

/*
 * This is very inefficient, but good enough for now!
 * Also thed payload will always fit, so no need to handle the MORE flag and
 * make this stateful.
 */
static ret_code cmd_media_get_poison_list(struct cxl_cmd *cmd,
                                          CXLDeviceState *cxl_dstate,
                                          uint16_t *len)
{
    struct get_poison_list_pl {
        uint64_t pa;
        uint64_t length;
    } QEMU_PACKED;

    struct get_poison_list_out_pl {
        uint8_t flags;
        uint8_t rsvd1;
        uint64_t overflow_timestamp;
        uint16_t count;
        uint8_t rsvd2[0x14];
        struct {
            uint64_t addr;
            uint32_t length;
            uint32_t resv;
        } QEMU_PACKED records[];
    } QEMU_PACKED;

    struct get_poison_list_pl *in = (void *)cmd->payload;
    struct get_poison_list_out_pl *out = (void *)cmd->payload;
    CXLType3Dev *ct3d = container_of(cxl_dstate, CXLType3Dev, cxl_dstate);
    CXLType3Class *cvc = CXL_TYPE3_GET_CLASS(ct3d);
    uint16_t record_count = 0, i = 0;
    uint64_t query_start = in->pa;
    uint64_t query_length = in->length;
    CXLPoisonList *poison_list;
    CXLPoison *ent;
    uint16_t out_pl_len;

    poison_list = cvc->get_poison_list(ct3d);

    QLIST_FOREACH(ent, poison_list, node) {
        /* Check for no overlap */
        if (ent->start >= query_start + query_length ||
            ent->start + ent->length <= query_start) {
            continue;
        }
        if (record_count == 256) {
            /* For now just return 256 max */
            break;
        }
        record_count++;
    }
    out_pl_len = sizeof(*out) + record_count * sizeof(out->records[0]);
    assert(out_pl_len <= CXL_MAILBOX_MAX_PAYLOAD_SIZE);

    memset(out, 0, out_pl_len);
    QLIST_FOREACH(ent, poison_list, node) {
        uint64_t start, stop;

        /* Check for no overlap */
        if (ent->start >= query_start + query_length ||
            ent->start + ent->length <= query_start) {
            continue;
        }
        if (i == 256) {
            break;
        }
        /* Deal with overlap */
        start = MAX(ent->start & 0xffffffffffffffc0, query_start);
        stop = MIN((ent->start & 0xffffffffffffffc0) + ent->length,
                   query_start + query_length);
        out->records[i].addr = start | 0x2; /* internal error */
        out->records[i].length = (stop - start) / 64;
        i++;
    }
    out->count = record_count;
    *len = out_pl_len;
    return CXL_MBOX_SUCCESS;
}

#define IMMEDIATE_CONFIG_CHANGE (1 << 1)
#define IMMEDIATE_DATA_CHANGE (1 << 2)
#define IMMEDIATE_POLICY_CHANGE (1 << 3)
#define IMMEDIATE_LOG_CHANGE (1 << 4)

static struct cxl_cmd cxl_cmd_set[256][256] = {
    [EVENTS][GET_RECORDS] = { "EVENTS_GET_RECORDS",
        cmd_events_get_records, 1, 0 },
    [EVENTS][CLEAR_RECORDS] = { "EVENTS_CLEAR_RECORDS",
        cmd_events_clear_records, ~0, IMMEDIATE_LOG_CHANGE },
    [EVENTS][GET_INTERRUPT_POLICY] = { "EVENTS_GET_INTERRUPT_POLICY",
        cmd_events_get_interrupt_policy, 0, 0 },
    [EVENTS][SET_INTERRUPT_POLICY] = { "EVENTS_SET_INTERRUPT_POLICY",
        cmd_events_set_interrupt_policy, 4, IMMEDIATE_CONFIG_CHANGE },
    [FIRMWARE_UPDATE][GET_INFO] = { "FIRMWARE_UPDATE_GET_INFO",
        cmd_firmware_update_get_info, 0, 0 },
    [TIMESTAMP][GET] = { "TIMESTAMP_GET", cmd_timestamp_get, 0, 0 },
    [TIMESTAMP][SET] = { "TIMESTAMP_SET", cmd_timestamp_set, 8, IMMEDIATE_POLICY_CHANGE },
    [LOGS][GET_SUPPORTED] = { "LOGS_GET_SUPPORTED", cmd_logs_get_supported, 0, 0 },
    [LOGS][GET_LOG] = { "LOGS_GET_LOG", cmd_logs_get_log, 0x18, 0 },
    [IDENTIFY][MEMORY_DEVICE] = { "IDENTIFY_MEMORY_DEVICE",
        cmd_identify_memory_device, 0, 0 },
    [CCLS][GET_PARTITION_INFO] = { "CCLS_GET_PARTITION_INFO",
        cmd_ccls_get_partition_info, 0, 0 },
    [CCLS][GET_LSA] = { "CCLS_GET_LSA", cmd_ccls_get_lsa, 8, 0 },
    [CCLS][SET_LSA] = { "CCLS_SET_LSA", cmd_ccls_set_lsa,
        ~0, IMMEDIATE_CONFIG_CHANGE | IMMEDIATE_DATA_CHANGE },
    [MEDIA_AND_POISON][GET_POISON_LIST] = { "MEDIA_AND_POISON_GET_POISON_LIST",
        cmd_media_get_poison_list, 16, 0 },
};

static struct cxl_cmd cxl_cmd_set_sw[256][256] = {
    [INFOSTAT][IS_IDENTIFY] = { "IDENTIFY", cmd_infostat_identify, 0, 18 },
    [INFOSTAT][BACKGROUND_OPERATION_STATUS] = { "BACKGROUND_OPERATION_STATUS",
        cmd_infostat_bg_op_sts, 0, 8 },
    /*
     * TODO get / set response message limit - requires all messages over
     * 256 bytes to support chunking.
     */
    [TIMESTAMP][GET] = { "TIMESTAMP_GET", cmd_timestamp_get, 0, 0 },
    [TIMESTAMP][SET] = { "TIMESTAMP_SET", cmd_timestamp_set, 8, IMMEDIATE_POLICY_CHANGE },
    [LOGS][GET_SUPPORTED] = { "LOGS_GET_SUPPORTED", cmd_logs_get_supported, 0, 0 },
    [LOGS][GET_LOG] = { "LOGS_GET_LOG", cmd_logs_get_log, 0x18, 0 },
    [PHYSICAL_SWITCH][IDENTIFY_SWITCH_DEVICE] = {"IDENTIFY_SWITCH_DEVICE",
        cmd_identify_switch_device, 0, 0x49 },
};

void cxl_process_mailbox(CXLDeviceState *cxl_dstate)
{
    uint16_t ret = CXL_MBOX_SUCCESS;
    struct cxl_cmd *cxl_cmd;
    uint64_t status_reg;
    opcode_handler h;
    uint64_t command_reg = cxl_dstate->mbox_reg_state64[R_CXL_DEV_MAILBOX_CMD];

    uint8_t set = FIELD_EX64(command_reg, CXL_DEV_MAILBOX_CMD, COMMAND_SET);
    uint8_t cmd = FIELD_EX64(command_reg, CXL_DEV_MAILBOX_CMD, COMMAND);
    uint16_t len = FIELD_EX64(command_reg, CXL_DEV_MAILBOX_CMD, LENGTH);
    cxl_cmd = &cxl_dstate->cxl_cmd_set[set][cmd];
    h = cxl_cmd->handler;
    if (h) {
        if (len == cxl_cmd->in || cxl_cmd->in == ~0) {
            cxl_cmd->payload = cxl_dstate->mbox_reg_state +
                A_CXL_DEV_CMD_PAYLOAD;
            ret = (*h)(cxl_cmd, cxl_dstate, &len);
            assert(len <= cxl_dstate->payload_size);
        } else {
            ret = CXL_MBOX_INVALID_PAYLOAD_LENGTH;
        }
    } else {
        qemu_log_mask(LOG_UNIMP, "Command %04xh not implemented\n",
                      set << 8 | cmd);
        ret = CXL_MBOX_UNSUPPORTED;
    }

    /* Set the return code */
    status_reg = FIELD_DP64(0, CXL_DEV_MAILBOX_STS, ERRNO, ret);

    /* Set the return length */
    command_reg = FIELD_DP64(command_reg, CXL_DEV_MAILBOX_CMD, COMMAND_SET, 0);
    command_reg = FIELD_DP64(command_reg, CXL_DEV_MAILBOX_CMD, COMMAND, 0);
    command_reg = FIELD_DP64(command_reg, CXL_DEV_MAILBOX_CMD, LENGTH, len);

    cxl_dstate->mbox_reg_state64[R_CXL_DEV_MAILBOX_CMD] = command_reg;
    cxl_dstate->mbox_reg_state64[R_CXL_DEV_MAILBOX_STS] = status_reg;

    /* Tell the host we're done */
    ARRAY_FIELD_DP32(cxl_dstate->mbox_reg_state32, CXL_DEV_MAILBOX_CTRL,
                     DOORBELL, 0);
}

void cxl_initialize_mailbox(CXLDeviceState *cxl_dstate, bool switch_cci)
{
    if (!switch_cci) {
        cxl_dstate->cxl_cmd_set = cxl_cmd_set;
    } else {
        cxl_dstate->cxl_cmd_set = cxl_cmd_set_sw;
    }

    for (int set = 0; set < 256; set++) {
        for (int cmd = 0; cmd < 256; cmd++) {
            if (cxl_dstate->cxl_cmd_set[set][cmd].handler) {
                struct cxl_cmd *c = &cxl_dstate->cxl_cmd_set[set][cmd];
                struct cel_log *log =
                    &cxl_dstate->cel_log[cxl_dstate->cel_size];

                log->opcode = (set << 8) | cmd;
                log->effect = c->effect;
                cxl_dstate->cel_size++;
            }
        }
    }
}
