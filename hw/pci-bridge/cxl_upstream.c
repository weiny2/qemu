/*
 * Emulated CXL Switch Upstream Port
 *
 * Copyright (c) 2022 Huawei Technologies.
 *
 * Based on xio31130_upstream.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "hw/pci/msi.h"
#include "hw/pci/pcie.h"
#include "hw/pci/pcie_port.h"

#define CXL_UPSTREAM_PORT_MSI_NR_VECTOR 1

#define CXL_UPSTREAM_PORT_MSI_OFFSET 0x70
#define CXL_UPSTREAM_PORT_PCIE_CAP_OFFSET 0x90
#define CXL_UPSTREAM_PORT_AER_OFFSET 0x100
#define CXL_UPSTREAM_PORT_DVSEC_OFFSET \
    (CXL_UPSTREAM_PORT_AER_OFFSET + PCI_ERR_SIZEOF)

typedef struct CXLUpstreamPort {
    /*< private >*/
    PCIEPort parent_obj;

    /*< public >*/
    CXLComponentState cxl_cstate;
} CXLUpstreamPort;

CXLComponentState *cxl_usp_to_cstate(CXLUpstreamPort *usp)
{
    return &usp->cxl_cstate;
}

static void cxl_filtered_pci_bridge_write_config(PCIDevice *d, uint32_t address,
                                                 uint32_t val, int len)
{
    if (ranges_overlap(address, len, PCI_BRIDGE_CONTROL, 1)) {
        CXLUpstreamPort *usp = CXL_USP(d);
        int byte = PCI_BRIDGE_CONTROL - address;
        uint16_t cxl_port_ctl = pci_get_word(d->config +
                                             usp->cxl_cstate.dvsecs[EXTENSIONS_PORT_DVSEC].lob +
                                             PORT_CONTROL_OFFSET);
        /*
         * If UNMASK SBR is not set, then the SBR bit in Bridge Control register
         * has no affect (CXL 2.0 8.5.1.2 Port Control Extensions).
         * Hence mask it out.
         */
        if (!(cxl_port_ctl & PORT_CONTROL_UNMASK_SBR)) {
            val &= ~(PCI_BRIDGE_CTL_BUS_RESET << (byte * 8));
        }
    }

    pci_bridge_write_config(d, address, val, len);
}

static void cxl_usp_dvsec_write_config(PCIDevice *dev, uint32_t addr,
                                       uint32_t val, int len)
{
    CXLUpstreamPort *usp = CXL_USP(dev);

    if (range_contains(&usp->cxl_cstate.dvsecs[EXTENSIONS_PORT_DVSEC], addr)) {
        uint8_t *reg = &dev->config[addr];
        addr -= usp->cxl_cstate.dvsecs[EXTENSIONS_PORT_DVSEC].lob;
        if (addr == PORT_CONTROL_OFFSET) {
            if (pci_get_word(reg) & PORT_CONTROL_ALT_MEMID_EN) {
                /* Alt Memory & ID Space Enable */
                qemu_log_mask(LOG_UNIMP,
                              "Alt Memory & ID space is not supported\n");
            }
        }
    }
    if (range_contains(&usp->cxl_cstate.dvsecs[PCIE_CXL_DEVICE_DVSEC], addr)) {
        uint16_t offset = usp->cxl_cstate.dvsecs[PCIE_CXL_DEVICE_DVSEC].lob;

        addr -= offset;
        if (addr == offsetof(CXLDVSECDevice, lock)) {
            if (val & 0x1) {
                /*
                 * If lock is set, change write masks to prevent updates to
                 * locked registers in config space.
                 */
                dev->wmask[offset + offsetof(CXLDVSECDevice, ctrl)] = 0;
                dev->wmask[offset + offsetof(CXLDVSECDevice, range1_base_hi)] = 0;
                dev->wmask[offset + offsetof(CXLDVSECDevice, range1_base_lo)] = 0;
                dev->wmask[offset + offsetof(CXLDVSECDevice, range2_base_hi)] = 0;
                dev->wmask[offset + offsetof(CXLDVSECDevice, range2_base_lo)] = 0;
            }
        }
    }
}

static void cxl_usp_write_config(PCIDevice *d, uint32_t address,
                                 uint32_t val, int len)
{
    cxl_filtered_pci_bridge_write_config(d, address, val, len);
    pcie_cap_flr_write_config(d, address, val, len);
    pcie_aer_write_config(d, address, val, len);

    cxl_usp_dvsec_write_config(d, address, val, len);
}

static void latch_registers(CXLUpstreamPort *usp)
{
    uint32_t *reg_state = usp->cxl_cstate.crb.cache_mem_registers;
    uint32_t *write_msk = usp->cxl_cstate.crb.cache_mem_regs_write_mask;

    cxl_component_register_init_common(reg_state, write_msk,
                                       CXL2_UPSTREAM_PORT);
    ARRAY_FIELD_DP32(reg_state, CXL_HDM_DECODER_CAPABILITY, TARGET_COUNT, 8);
}

static void cxl_usp_reset(DeviceState *qdev)
{
    PCIDevice *d = PCI_DEVICE(qdev);
    CXLUpstreamPort *usp = CXL_USP(qdev);

    pci_bridge_reset(qdev);
    pcie_cap_deverr_reset(d);
    latch_registers(usp);
}

static void build_dvsecs(CXLComponentState *cxl)
{
    uint8_t *dvsec;

    dvsec = (uint8_t *)&(CXLDVSECPortExtensions){
        .status = 0x1, /* Port Power Management Init Complete */
    };
    cxl_component_create_dvsec(cxl, CXL2_UPSTREAM_PORT,
                               EXTENSIONS_PORT_DVSEC_LENGTH,
                               EXTENSIONS_PORT_DVSEC,
                               EXTENSIONS_PORT_DVSEC_REVID, dvsec);
    dvsec = (uint8_t *)&(CXLDVSECPortFlexBus){
        .cap                     = 0x27, /* Cache, IO, Mem, non-MLD */
        .ctrl                    = 0x27, /* Cache, IO, Mem */
        .status                  = 0x26, /* same */
        .rcvd_mod_ts_data_phase1 = 0xef, /* WTF? */
    };
    cxl_component_create_dvsec(cxl, CXL2_UPSTREAM_PORT,
                               PCIE_FLEXBUS_PORT_DVSEC_LENGTH_2_0,
                               PCIE_FLEXBUS_PORT_DVSEC,
                               PCIE_FLEXBUS_PORT_DVSEC_REVID_2_0, dvsec);

    dvsec = (uint8_t *)&(CXLDVSECRegisterLocator){
        .rsvd         = 0,
        .reg0_base_lo = RBI_COMPONENT_REG | CXL_COMPONENT_REG_BAR_IDX,
        .reg0_base_hi = 0,
    };
    cxl_component_create_dvsec(cxl, CXL2_UPSTREAM_PORT,
                               REG_LOC_DVSEC_LENGTH, REG_LOC_DVSEC,
                               REG_LOC_DVSEC_REVID, dvsec);
}

static void cxl_usp_realize(PCIDevice *d, Error **errp)
{
    PCIEPort *p = PCIE_PORT(d);
    CXLUpstreamPort *usp = CXL_USP(d);
    CXLComponentState *cxl_cstate = &usp->cxl_cstate;
    ComponentRegisters *cregs = &cxl_cstate->crb;
    MemoryRegion *component_bar = &cregs->component_registers;
    int rc;

    pci_bridge_initfn(d, TYPE_PCIE_BUS);
    pcie_port_init_reg(d);

    rc = msi_init(d, CXL_UPSTREAM_PORT_MSI_OFFSET,
                  CXL_UPSTREAM_PORT_MSI_NR_VECTOR, true, true, errp);
    if (rc) {
        assert(rc == -ENOTSUP);
        goto err_bridge;
    }

    rc = pcie_cap_init(d, CXL_UPSTREAM_PORT_PCIE_CAP_OFFSET,
                       PCI_EXP_TYPE_UPSTREAM, p->port, errp);
    if (rc < 0) {
        goto err_msi;
    }

    pcie_cap_flr_init(d);
    pcie_cap_deverr_init(d);
    rc = pcie_aer_init(d, PCI_ERR_VER, CXL_UPSTREAM_PORT_AER_OFFSET,
                       PCI_ERR_SIZEOF, errp);
    if (rc) {
        goto err_cap;
    }

    cxl_cstate->dvsec_offset = CXL_UPSTREAM_PORT_DVSEC_OFFSET;
    cxl_cstate->pdev = d;
    build_dvsecs(cxl_cstate);
    cxl_component_register_block_init(OBJECT(d), cxl_cstate, TYPE_CXL_USP);
    pci_register_bar(d, CXL_COMPONENT_REG_BAR_IDX,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_TYPE_64,
                     component_bar);

    return;

err_cap:
    pcie_cap_exit(d);
err_msi:
    msi_uninit(d);
err_bridge:
    pci_bridge_exitfn(d);
}

static void cxl_usp_exitfn(PCIDevice *d)
{
    pcie_aer_exit(d);
    pcie_cap_exit(d);
    msi_uninit(d);
    pci_bridge_exitfn(d);
}

static void cxl_upstream_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(oc);

    k->is_bridge = true;
    k->config_write = cxl_usp_write_config;
    k->realize = cxl_usp_realize;
    k->exit = cxl_usp_exitfn;
    k->vendor_id = 0x19e5; /* Huawei */
    k->device_id = 0xa128; /* Emulated CXL Switch Upstream Port */
    k->revision = 0;
    set_bit(DEVICE_CATEGORY_BRIDGE, dc->categories);
    dc->desc = "CXL Switch Upstream Port";
    dc->reset = cxl_usp_reset;
}

static const TypeInfo cxl_usp_info = {
    .name = TYPE_CXL_USP,
    .parent = TYPE_PCIE_PORT,
    .instance_size = sizeof(CXLUpstreamPort),
    .class_init = cxl_upstream_class_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { INTERFACE_CXL_DEVICE },
        { }
    },
};

static void cxl_usp_register_type(void)
{
    type_register_static(&cxl_usp_info);
}

type_init(cxl_usp_register_type);
