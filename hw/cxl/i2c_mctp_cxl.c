/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Emulation of a CXL Switch Fabric Management interface over MCTP over I2C.
 *
 * Copyright (c) 2023 Huawei Technologies.
 *
 * Reference list:
 * From www.dmtf.org
 * DSP0236 Management Component Transport Protocol (MCTP) Base Specification 1.3.0
 * DPS0234 CXL Fabric Manager API over MCTP Binding Specification 1.0.0
 * DSP0281 CXL Type 3 Deivce Component Command Interface over MCTP Binding
 *    Specification (note some commands apply to switches as well)
 * From www.computeexpresslink.org
 * Compute Express Link (CXL) Specification revision 3.0 Version 1.0
 */

#include "qemu/osdep.h"
#include "hw/i2c/i2c.h"
#include "hw/i2c/mctp.h"
#include "hw/irq.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "hw/cxl/cxl.h"
#include "hw/cxl/cxl_fmapi.h"
#include "hw/pci/pcie.h"
#include "hw/pci/pcie_port.h"
#include "hw/qdev-properties.h"

#define TYPE_I2C_MCTP_CXL "i2c_mctp_cxl"

#define MCTP_CXL_MAX_MSG_LEN 1088 /* CXL FMAPI binding spec */

typedef struct CXLMCTPMessage {
    /*
     * DSP0236 (MCTP Base) Integrity Check + Message Type
     * DSP0234/DSP0281 (CXL bindings) state no Integrity Check
     * so just the message type.
     */
    uint8_t message_type;
    /* Remaing fields from CXL r3.0 Table 7-14 CCI Message Format */
    uint8_t category;
    uint8_t tag;
    uint8_t rsvd;
    /*
     * CXL r3.0 - Table 8-36 Generic Component Command Opcodes:
     * Command opcode is split into two sub fields
     */
    uint8_t command;
    uint8_t command_set;
    uint8_t pl_length[3];
    uint16_t vendor_tatus;
    uint16_t rc;
    uint8_t payload[];
} QEMU_PACKED CXLMCTPMessage;

enum cxl_dev_type {
    cxl_type3,
    cxl_switch,
};

struct I2C_MCTP_CXL_State {
    MCTPI2CEndpoint mctp;
    PCIDevice *target;
    enum cxl_dev_type type;
    size_t len;
    int64_t pos;
    uint8_t buffer[MCTP_CXL_MAX_MSG_LEN];
    uint8_t scratch[MCTP_CXL_MAX_MSG_LEN];
};

OBJECT_DECLARE_SIMPLE_TYPE(I2C_MCTP_CXL_State, I2C_MCTP_CXL)

static void cxl_cci_cmd_set_info_and_status_parse(I2C_MCTP_CXL_State *s,
                                                  CXLMCTPMessage *msg)
{
    CXLMCTPMessage *out = (void *)s->scratch;
    PCIDeviceClass *class = PCI_DEVICE_GET_CLASS(s->target);

    switch (msg->command) {
    case CXL_CCI_INFOSTAT_IDENTIFY:
    {
        struct cxl_cci_infostat_identify_resp_pl *pl =
            (struct cxl_cci_infostat_identify_resp_pl *)&s->scratch[s->pos];

        *pl = (struct cxl_cci_infostat_identify_resp_pl) {
            .vendor_id = class->vendor_id,
            .device_id = class->device_id,
            .subsystem_vendor_id = class->subsystem_vendor_id,
            .subsystem_id = class->subsystem_id,
            /* TODO : Get serial number  - a bit fiddly */
            .max_msg = 9, /* 512 - no need to chunk mctp for this */
        };
        switch (s->type) {
        case cxl_type3:
            pl->component_type = 0x3;
            break;
        case cxl_switch:
            pl->component_type = 0x0;
            break;
        }

        s->len += sizeof(*pl);
        out->rc = CXL_MBOX_SUCCESS;
        return;
    }

    default:
        out->rc = CXL_MBOX_UNSUPPORTED;
        return;
    }
}

/* May make sense to push some of this to individual device emulation */
static void cxl_fmapi_cmd_set_physical_switch_parse(I2C_MCTP_CXL_State *s,
                                                    CXLMCTPMessage *msg)
{
    CXLMCTPMessage *out = (void *)s->scratch;

    if (s->type != cxl_switch) {
        /* TODO: Rename return codes as used for this as well as mailbox */
        out->rc = CXL_MBOX_UNSUPPORTED;
        return;
    }

    switch (msg->command) {
    case CXL_FMAPI_PHYSICAL_SWITCH_IDENTIFY_SWITCH:
    {
        PCIEPort *usp = PCIE_PORT(s->target);
        PCIBus *bus = &PCI_BRIDGE(s->target)->sec_bus;
        struct cxl_fmapi_ident_switch_dev_resp_pl *pl =
            (struct cxl_fmapi_ident_switch_dev_resp_pl *)&s->scratch[s->pos];
        int num_phys_ports = pcie_count_ds_ports(bus);
        int devfn;

        *pl = (struct cxl_fmapi_ident_switch_dev_resp_pl) {
             /* TODO: Should be parameterized to support multiple instances */
            .ingres_port_id = 0,
            .num_physical_ports = num_phys_ports + 1, /* 1 USP */
            .num_vcs = 1, /* Not yet support multiple VCS - potentialy tricky */
            .active_vcs_bitmask[0] = 0x1,
            .num_total_vppb = num_phys_ports + 1,
            .num_active_vppb = num_phys_ports + 1,
            .num_hdm_decoders = 4,
        };

        /* Fill in the active ports bitmask with all USP and DSP port numbers */
        for (devfn = 0; devfn < ARRAY_SIZE(bus->devices); devfn++) {
            PCIDevice *d = bus->devices[devfn];

            if (!d || !pci_is_express(d) || !d->exp.exp_cap) {
                continue;
            }
            if (object_dynamic_cast(OBJECT(d), TYPE_PCIE_PORT)) {
                PCIEPort *port = PCIE_PORT(d);
                uint8_t portnum = port->port;
                pl->active_port_bitmask[portnum / 8] |= (1 << portnum % 8);
            }
        }
        pl->active_port_bitmask[usp->port / 8] |= (1 << usp->port % 8);

        s->len += sizeof(*pl);
        out->rc = CXL_MBOX_SUCCESS;

        return;
    }

    case CXL_FMAPI_GET_PHYSICAL_PORT_STATE:
    {
        size_t pl_size;
        uint8_t num_ports = msg->payload[0];
        int num_phys_ports = pcie_count_ds_ports(&PCI_BRIDGE(s->target)->sec_bus);
        struct cxl_fmapi_get_phys_port_state_resp_pl *pl =
            (struct cxl_fmapi_get_phys_port_state_resp_pl *)&s->scratch[s->pos];
        int i;

        /* TODO: Should match against particular ports requested... */
        pl->num_ports = num_phys_ports;
        for (i = 0; i < pl->num_ports; i++) {
            struct cxl_fmapi_port_state_info_block *port;
            port = &pl->ports[i];
            port->port_id = i; /* TODO: Right port number */
            if (port->port_id < 1) { /* 1 upstream ports */
                port->config_state = 4;
                port->connected_device_type = 0;
            } else { /* remainder downstream ports */
                port->config_state = 3;
                port->connected_device_type = 4; /* TODO: Check. CXL type 3 */
                port->supported_ld_count = 3;
            }
            port->connected_device_cxl_version = 2;
            port->port_cxl_version_bitmask = 0x2;
            port->max_link_width = 0x10; /* x16 */
            port->negotiated_link_width = 0x10;
            port->supported_link_speeds_vector = 0x1c; /* 8, 16, 32 GT/s */
            port->max_link_speed = 5;
            port->current_link_speed = 5; /* 32 */
            port->ltssm_state = 0x7; /* L2 */
            port->first_lane_num = 0;
            port->link_state = 0;
        }

        pl_size = sizeof(pl) + sizeof(*pl->ports) * num_ports;

        st24_le_p(out->pl_length, pl_size);
        s->len += pl_size;
        msg->rc = CXL_MBOX_SUCCESS;

        return;
    }

    default:
        msg->rc = CXL_MBOX_UNSUPPORTED;
        return;
    }
}

static Property i2c_mctp_cxl_props[] = {
    DEFINE_PROP_LINK("target", I2C_MCTP_CXL_State,
                     target, TYPE_PCI_DEVICE, PCIDevice *),
    DEFINE_PROP_END_OF_LIST(),
};

static size_t i2c_mctp_cxl_get_message_bytes(MCTPI2CEndpoint *mctp,
                                             uint8_t *buf,
                                             size_t maxlen,
                                             uint8_t *mctp_flags)
{
    I2C_MCTP_CXL_State *s = I2C_MCTP_CXL(mctp);
    size_t len;

    len = MIN(maxlen, s->len - s->pos);

    if (len == 0) {
        return 0;
    }

    if (s->pos == 0) {
        *mctp_flags |= MCTP_H_FLAGS_SOM;
    }

    memcpy(buf, s->scratch + s->pos, len);
    s->pos += len;

    if (s->pos == s->len) {
        *mctp_flags |= MCTP_H_FLAGS_EOM;

        s->pos = s->len = 0;
    }

    return len;
}

static int i2c_mctp_cxl_put_message_bytes(MCTPI2CEndpoint *mctp,
                                          uint8_t *buf, size_t len)
{
    I2C_MCTP_CXL_State *s = I2C_MCTP_CXL(mctp);

    if (s->len + len > MCTP_CXL_MAX_MSG_LEN) {
        return -1;
    }

    memcpy(s->buffer + s->len, buf, len);
    s->len += len;

    return 0;
}

static size_t i2c_mctp_cxl_get_message_types(MCTPI2CEndpoint *mctp,
                                             uint8_t *data,
                                             size_t maxlen)
{
    uint8_t buf[] = {
        0x0, 0x7, 0x8, /* Control, CXL FM-API and CXL CCI */
    };

    memcpy(data, buf, sizeof(buf));

    return sizeof(buf);
}

static void i2c_mctp_cxl_reset_message(MCTPI2CEndpoint *mctp)
{
    I2C_MCTP_CXL_State *s = I2C_MCTP_CXL(mctp);

    s->len = 0;
}

static void i2c_mctp_cxl_handle_message(MCTPI2CEndpoint *mctp)
{
    I2C_MCTP_CXL_State *s = I2C_MCTP_CXL(mctp);
    CXLMCTPMessage *msg = (CXLMCTPMessage *)s->buffer;
    CXLMCTPMessage buf = {
        .message_type = msg->message_type,
        .category = 1,
        .tag = msg->tag,
        .command = msg->command,
        .command_set = msg->command_set,
    };

    memcpy(s->scratch, &buf, sizeof(buf));
    s->pos = sizeof(buf);

    switch (msg->message_type) {
    case 0x7:
        switch (msg->command_set)  {
        case CXL_FMAPI_CMD_SET_PHYSICAL_SWITCH:
            cxl_fmapi_cmd_set_physical_switch_parse(s, msg);
            break;
        }
        break;
    case 0x8:
        switch (msg->command_set) {
        case CXL_CCI_CMD_SET_INFOSTAT:
            cxl_cci_cmd_set_info_and_status_parse(s, msg);
            break;
        }
        break;
    }
    s->pos = 0;

    i2c_mctp_schedule_send(mctp);
}

static void i2c_mctp_cxl_realize(DeviceState *d, Error **errp)
{
    I2C_MCTP_CXL_State *s = I2C_MCTP_CXL(d);

    /* Check this is a type we support */
    if (object_dynamic_cast(OBJECT(s->target), TYPE_CXL_USP)) {
        s->type = cxl_switch;
        return;
    }

    if (object_dynamic_cast(OBJECT(s->target), TYPE_CXL_TYPE3)) {
        s->type = cxl_type3;
        return;
    }
    error_setg(errp, "Unhandled target type for CXL MCTP EP");
}

static void i2c_mctp_cxl_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    MCTPI2CEndpointClass *mc = MCTP_I2C_ENDPOINT_CLASS(klass);

    dc->realize = i2c_mctp_cxl_realize;
    mc->get_message_types = i2c_mctp_cxl_get_message_types;
    mc->get_message_bytes = i2c_mctp_cxl_get_message_bytes;
    mc->put_message_bytes = i2c_mctp_cxl_put_message_bytes;

    mc->handle_message = i2c_mctp_cxl_handle_message;
    mc->reset_message = i2c_mctp_cxl_reset_message;
    device_class_set_props(dc, i2c_mctp_cxl_props);
}

static const TypeInfo i2c_mctp_cxl_info = {
    .name = TYPE_I2C_MCTP_CXL,
    .parent = TYPE_MCTP_I2C_ENDPOINT,
    .instance_size = sizeof(I2C_MCTP_CXL_State),
    .class_init = i2c_mctp_cxl_class_init,
};

static void i2c_mctp_cxl_register_types(void)
{
    type_register_static(&i2c_mctp_cxl_info);
}

type_init(i2c_mctp_cxl_register_types)
