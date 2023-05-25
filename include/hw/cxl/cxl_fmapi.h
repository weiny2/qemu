/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * CXL Fabric Manager API definitions
 *
 * Copyright (c) 2023 Huawei Technologies.
 *
 * Refs to: Compute Express Link (CXL) Specification revision 3.0 Version 1.0
 * from www.computeexpresslink.org
 *
 * FM-API commands can be carried over various transports (MCTP, switch-CCI etc)
 * so define the payloads in a common header.
 */

#ifndef CXL_FMAPI_H
#define CXL_FMAPI_H

#include "qemu/osdep.h"

/*
 * TODO: Confirm which commands sent via FM-API binding and which via Type 3 CCI
 * binding.  For now I'm assuming only stuff in the FM-API table goes via
 * FM-API.
 */

/*
 * CXL r3.0 Table 8-36 Generic Component Command Opcodes
 */

/* CXL r3.0 8.2.9.1.1 Identify (Opcode 0001h) */
#define CXL_CCI_CMD_SET_INFOSTAT 0x00
#define   CXL_CCI_INFOSTAT_IDENTIFY 0x01

struct cxl_cci_infostat_identify_resp_pl {
    uint16_t vendor_id;
    uint16_t device_id;
    uint16_t subsystem_vendor_id;
    uint16_t subsystem_id;
    uint8_t serial_num[8];
    uint8_t max_msg;
    uint8_t component_type;
};

/*
 * CXL r3.0 7.6.7 Fabric Management Application Programming Interface
 */
#define CXL_FMAPI_CMD_SET_PHYSICAL_SWITCH 0x51
#define   CXL_FMAPI_PHYSICAL_SWITCH_IDENTIFY_SWITCH 0x00
#define   CXL_FMAPI_GET_PHYSICAL_PORT_STATE 0x01

/*
 * CXL r3.0 7.6.7.1.1 Identify Switch Device (Opcode 5100h)
 */
struct cxl_fmapi_ident_switch_dev_resp_pl {
    uint8_t ingres_port_id;
    uint8_t rsv1;
    uint8_t num_physical_ports;
    uint8_t num_vcs;
    uint8_t active_port_bitmask[32];
    uint8_t active_vcs_bitmask[32];
    uint16_t num_total_vppb;
    uint16_t num_active_vppb;
    uint8_t num_hdm_decoders;
} QEMU_PACKED;

/*
 * CXL r3.0 7.6.7.1.2 Get Physical Port State (Opcode 5101h)
 */

/* CXL r3.0 Table 7-18 Get Physical Port State Request Payload */
struct cxl_fmapi_get_phys_port_state_req_pl {
    uint8_t num_ports; /* CHECK. may get too large for MCTP message size */
    uint8_t ports[];
} QEMU_PACKED;

/* CXL r3.0 Table 7-20 Get Physical Port State Port Information Block Format */
struct cxl_fmapi_port_state_info_block {
    uint8_t port_id;
    uint8_t config_state;
    uint8_t connected_device_cxl_version;
    uint8_t rsv1;
    uint8_t connected_device_type;
    uint8_t port_cxl_version_bitmask;
    uint8_t max_link_width;
    uint8_t negotiated_link_width;
    uint8_t supported_link_speeds_vector;
    uint8_t max_link_speed;
    uint8_t current_link_speed;
    uint8_t ltssm_state;
    uint8_t first_lane_num;
    uint16_t link_state;
    uint8_t supported_ld_count;
} QEMU_PACKED;

/* CXL r3.0 Table 7-19 Get Physical Port State Response Payload */
struct cxl_fmapi_get_phys_port_state_resp_pl {
    uint8_t num_ports;
    uint8_t rsv1[3];
    struct cxl_fmapi_port_state_info_block ports[];
} QEMU_PACKED;

#endif /* CXL_FMAPI_H */
