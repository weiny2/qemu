#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/error-report.h"
#include "qapi/qapi-commands-cxl.h"
#include "hw/mem/memory-device.h"
#include "hw/mem/pc-dimm.h"
#include "hw/pci/pci.h"
#include "hw/qdev-properties.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/pmem.h"
#include "qemu/range.h"
#include "qemu/rcu.h"
#include "sysemu/hostmem.h"
#include "sysemu/numa.h"
#include "hw/cxl/cxl.h"
#include "hw/pci/msix.h"
#include "hw/pci/spdm.h"

#define DWORD_BYTE 4

/* Default CDAT entries for a memory region */
enum {
    CT3_CDAT_DSMAS,
    CT3_CDAT_DSLBIS0,
    CT3_CDAT_DSLBIS1,
    CT3_CDAT_DSLBIS2,
    CT3_CDAT_DSLBIS3,
    CT3_CDAT_DSEMTS,
    CT3_CDAT_NUM_ENTRIES
};

static int ct3_build_cdat_entries_for_mr(CDATSubHeader **cdat_table,
                                         int dsmad_handle, MemoryRegion *mr,
                                         bool is_pmem, uint64_t dpa_base)
{
    g_autofree CDATDsmas *dsmas = NULL;
    g_autofree CDATDslbis *dslbis0 = NULL;
    g_autofree CDATDslbis *dslbis1 = NULL;
    g_autofree CDATDslbis *dslbis2 = NULL;
    g_autofree CDATDslbis *dslbis3 = NULL;
    g_autofree CDATDsemts *dsemts = NULL;

    dsmas = g_malloc(sizeof(*dsmas));
    if (!dsmas) {
        return -ENOMEM;
    }
    *dsmas = (CDATDsmas) {
        .header = {
            .type = CDAT_TYPE_DSMAS,
            .length = sizeof(*dsmas),
        },
        .DSMADhandle = dsmad_handle,
        .flags = is_pmem ? CDAT_DSMAS_FLAG_NV : 0,
        .DPA_base = dpa_base,
        .DPA_length = int128_get64(mr->size),
    };

    /* For now, no memory side cache, plausiblish numbers */
    dslbis0 = g_malloc(sizeof(*dslbis0));
    if (!dslbis0) {
        return -ENOMEM;
    }
    *dslbis0 = (CDATDslbis) {
        .header = {
            .type = CDAT_TYPE_DSLBIS,
            .length = sizeof(*dslbis0),
        },
        .handle = dsmad_handle,
        .flags = HMAT_LB_MEM_MEMORY,
        .data_type = HMAT_LB_DATA_READ_LATENCY,
        .entry_base_unit = 10000, /* 10ns base */
        .entry[0] = 15, /* 150ns */
    };

    dslbis1 = g_malloc(sizeof(*dslbis1));
    if (!dslbis1) {
        return -ENOMEM;
    }
    *dslbis1 = (CDATDslbis) {
        .header = {
            .type = CDAT_TYPE_DSLBIS,
            .length = sizeof(*dslbis1),
        },
        .handle = dsmad_handle,
        .flags = HMAT_LB_MEM_MEMORY,
        .data_type = HMAT_LB_DATA_WRITE_LATENCY,
        .entry_base_unit = 10000,
        .entry[0] = 25, /* 250ns */
    };

    dslbis2 = g_malloc(sizeof(*dslbis2));
    if (!dslbis2) {
        return -ENOMEM;
    }
    *dslbis2 = (CDATDslbis) {
        .header = {
            .type = CDAT_TYPE_DSLBIS,
            .length = sizeof(*dslbis2),
        },
        .handle = dsmad_handle,
        .flags = HMAT_LB_MEM_MEMORY,
        .data_type = HMAT_LB_DATA_READ_BANDWIDTH,
        .entry_base_unit = 1000, /* GB/s */
        .entry[0] = 16,
    };

    dslbis3 = g_malloc(sizeof(*dslbis3));
    if (!dslbis3) {
        return -ENOMEM;
    }
    *dslbis3 = (CDATDslbis) {
        .header = {
            .type = CDAT_TYPE_DSLBIS,
            .length = sizeof(*dslbis3),
        },
        .handle = dsmad_handle,
        .flags = HMAT_LB_MEM_MEMORY,
        .data_type = HMAT_LB_DATA_WRITE_BANDWIDTH,
        .entry_base_unit = 1000, /* GB/s */
        .entry[0] = 16,
    };

    dsemts = g_malloc(sizeof(*dsemts));
    if (!dsemts) {
        return -ENOMEM;
    }
    *dsemts = (CDATDsemts) {
        .header = {
            .type = CDAT_TYPE_DSEMTS,
            .length = sizeof(*dsemts),
        },
        .DSMAS_handle = dsmad_handle,
        /* Reserved - the non volatile from DSMAS matters */
        .EFI_memory_type_attr = 2,
        .DPA_offset = 0,
        .DPA_length = int128_get64(mr->size),
    };

    /* Header always at start of structure */
    cdat_table[CT3_CDAT_DSMAS] = g_steal_pointer(&dsmas);
    cdat_table[CT3_CDAT_DSLBIS0] = g_steal_pointer(&dslbis0);
    cdat_table[CT3_CDAT_DSLBIS1] = g_steal_pointer(&dslbis1);
    cdat_table[CT3_CDAT_DSLBIS2] = g_steal_pointer(&dslbis2);
    cdat_table[CT3_CDAT_DSLBIS3] = g_steal_pointer(&dslbis3);
    cdat_table[CT3_CDAT_DSEMTS] = g_steal_pointer(&dsemts);

    return 0;
}

static int ct3_build_cdat_table(CDATSubHeader ***cdat_table, void *priv)
{
    g_autofree CDATSubHeader **table = NULL;
    CXLType3Dev *ct3d = priv;
    MemoryRegion *volatile_mr = NULL, *nonvolatile_mr = NULL;
    int dsmad_handle = 0;
    int cur_ent = 0;
    int len = 0;
    int rc;

    if (!ct3d->hostpmem && !ct3d->hostvmem) {
        return 0;
    }

    if (ct3d->hostvmem) {
        volatile_mr = host_memory_backend_get_memory(ct3d->hostvmem);
        if (!volatile_mr) {
            return -EINVAL;
        }
        len += CT3_CDAT_NUM_ENTRIES;
    }

    if (ct3d->hostpmem) {
        nonvolatile_mr = host_memory_backend_get_memory(ct3d->hostpmem);
        if (!nonvolatile_mr) {
            return -EINVAL;
        }
        len += CT3_CDAT_NUM_ENTRIES;
    }

    table = g_malloc0(len * sizeof(*table));
    if (!table) {
        return -ENOMEM;
    }

    /* Now fill them in */
    if (volatile_mr) {
        rc = ct3_build_cdat_entries_for_mr(table, dsmad_handle++, volatile_mr,
                true, 0);
        if (rc < 0) {
            return rc;
        }
        cur_ent = CT3_CDAT_NUM_ENTRIES;
    }

    if (nonvolatile_mr) {
        rc = ct3_build_cdat_entries_for_mr(&(table[cur_ent]), dsmad_handle++,
                nonvolatile_mr, true, (volatile_mr ? volatile_mr->size : 0));
        if (rc < 0) {
            goto error_cleanup;
        }
        cur_ent += CT3_CDAT_NUM_ENTRIES;
    }
    assert(len == cur_ent);

    *cdat_table = g_steal_pointer(&table);

    return len;
error_cleanup:
    int i;
    for (i = 0; i < cur_ent; i++) {
        g_free(*cdat_table[i]);
    }
    return rc;
}

static void ct3_free_cdat_table(CDATSubHeader **cdat_table, int num, void *priv)
{
    int i;

    for (i = 0; i < num; i++) {
        g_free(cdat_table[i]);
    }
    g_free(cdat_table);
}

static bool cxl_doe_cdat_rsp(DOECap *doe_cap)
{
    CDATObject *cdat = &CXL_TYPE3(doe_cap->pdev)->cxl_cstate.cdat;
    uint16_t ent;
    void *base;
    uint32_t len;
    CDATReq *req = pcie_doe_get_write_mbox_ptr(doe_cap);
    CDATRsp rsp;

    assert(cdat->entry_len);

    /* Discard if request length mismatched */
    if (pcie_doe_get_obj_len(req) <
        DIV_ROUND_UP(sizeof(CDATReq), DWORD_BYTE)) {
        return false;
    }

    ent = req->entry_handle;
    base = cdat->entry[ent].base;
    len = cdat->entry[ent].length;

    rsp = (CDATRsp) {
        .header = {
            .vendor_id = CXL_VENDOR_ID,
            .data_obj_type = CXL_DOE_TABLE_ACCESS,
            .reserved = 0x0,
            .length = DIV_ROUND_UP((sizeof(rsp) + len), DWORD_BYTE),
        },
        .rsp_code = CXL_DOE_TAB_RSP,
        .table_type = CXL_DOE_TAB_TYPE_CDAT,
        .entry_handle = (ent < cdat->entry_len - 1) ?
                        ent + 1 : CXL_DOE_TAB_ENT_MAX,
    };

    memcpy(doe_cap->read_mbox, &rsp, sizeof(rsp));
    memcpy(doe_cap->read_mbox + DIV_ROUND_UP(sizeof(rsp), DWORD_BYTE),
           base, len);

    doe_cap->read_mbox_len += rsp.header.length;

    return true;
}

static bool cxl_doe_compliance_rsp(DOECap *doe_cap)
{
    CXLCompRsp *rsp = &CXL_TYPE3(doe_cap->pdev)->cxl_cstate.compliance.response;
    CXLCompReqHeader *req = pcie_doe_get_write_mbox_ptr(doe_cap);
    uint32_t req_len = 0, rsp_len = 0;
    CXLCompType type = req->req_code;

    switch (type) {
    case CXL_COMP_MODE_CAP:
        req_len = sizeof(CXLCompCapReq);
        rsp_len = sizeof(CXLCompCapRsp);
        rsp->cap_rsp.status = 0x0;
        rsp->cap_rsp.available_cap_bitmask = 0;
        rsp->cap_rsp.enabled_cap_bitmask = 0;
        break;
    case CXL_COMP_MODE_STATUS:
        req_len = sizeof(CXLCompStatusReq);
        rsp_len = sizeof(CXLCompStatusRsp);
        rsp->status_rsp.cap_bitfield = 0;
        rsp->status_rsp.cache_size = 0;
        rsp->status_rsp.cache_size_units = 0;
        break;
    case CXL_COMP_MODE_HALT:
        req_len = sizeof(CXLCompHaltReq);
        rsp_len = sizeof(CXLCompHaltRsp);
        break;
    case CXL_COMP_MODE_MULT_WR_STREAM:
        req_len = sizeof(CXLCompMultiWriteStreamingReq);
        rsp_len = sizeof(CXLCompMultiWriteStreamingRsp);
        break;
    case CXL_COMP_MODE_PRO_CON:
        req_len = sizeof(CXLCompProducerConsumerReq);
        rsp_len = sizeof(CXLCompProducerConsumerRsp);
        break;
    case CXL_COMP_MODE_BOGUS:
        req_len = sizeof(CXLCompBogusWritesReq);
        rsp_len = sizeof(CXLCompBogusWritesRsp);
        break;
    case CXL_COMP_MODE_INJ_POISON:
        req_len = sizeof(CXLCompInjectPoisonReq);
        rsp_len = sizeof(CXLCompInjectPoisonRsp);
        break;
    case CXL_COMP_MODE_INJ_CRC:
        req_len = sizeof(CXLCompInjectCrcReq);
        rsp_len = sizeof(CXLCompInjectCrcRsp);
        break;
    case CXL_COMP_MODE_INJ_FC:
        req_len = sizeof(CXLCompInjectFlowCtrlReq);
        rsp_len = sizeof(CXLCompInjectFlowCtrlRsp);
        break;
    case CXL_COMP_MODE_TOGGLE_CACHE:
        req_len = sizeof(CXLCompToggleCacheFlushReq);
        rsp_len = sizeof(CXLCompToggleCacheFlushRsp);
        break;
    case CXL_COMP_MODE_INJ_MAC:
        req_len = sizeof(CXLCompInjectMacDelayReq);
        rsp_len = sizeof(CXLCompInjectMacDelayRsp);
        break;
    case CXL_COMP_MODE_INS_UNEXP_MAC:
        req_len = sizeof(CXLCompInsertUnexpMacReq);
        rsp_len = sizeof(CXLCompInsertUnexpMacRsp);
        break;
    case CXL_COMP_MODE_INJ_VIRAL:
        req_len = sizeof(CXLCompInjectViralReq);
        rsp_len = sizeof(CXLCompInjectViralRsp);
        break;
    case CXL_COMP_MODE_INJ_ALMP:
        req_len = sizeof(CXLCompInjectAlmpReq);
        rsp_len = sizeof(CXLCompInjectAlmpRsp);
        break;
    case CXL_COMP_MODE_IGN_ALMP:
        req_len = sizeof(CXLCompIgnoreAlmpReq);
        rsp_len = sizeof(CXLCompIgnoreAlmpRsp);
        break;
    case CXL_COMP_MODE_INJ_BIT_ERR:
        req_len = sizeof(CXLCompInjectBitErrInFlitReq);
        rsp_len = sizeof(CXLCompInjectBitErrInFlitRsp);
        break;
    default:
        break;
    }

    /* Discard if request length mismatched */
    if (pcie_doe_get_obj_len(req) < DIV_ROUND_UP(req_len, DWORD_BYTE)) {
        return false;
    }

    /* Common fields for each compliance type */
    rsp->header.doe_header.vendor_id = CXL_VENDOR_ID;
    rsp->header.doe_header.data_obj_type = CXL_DOE_COMPLIANCE;
    rsp->header.doe_header.length = DIV_ROUND_UP(rsp_len, DWORD_BYTE);
    rsp->header.rsp_code = type;
    rsp->header.version = 0x1;
    rsp->header.length = rsp_len;

    memcpy(doe_cap->read_mbox, rsp, rsp_len);

    doe_cap->read_mbox_len += rsp->header.doe_header.length;

    return true;
}

static uint32_t ct3d_config_read(PCIDevice *pci_dev, uint32_t addr, int size)
{
    CXLType3Dev *ct3d = CXL_TYPE3(pci_dev);
    uint32_t val;

    if (pcie_doe_read_config(&ct3d->doe_cdat, addr, size, &val)) {
        return val;
    } else if (pcie_doe_read_config(&ct3d->doe_comp, addr, size, &val)) {
        return val;
    } else if (ct3d->spdm_port &&
               pcie_doe_read_config(&ct3d->doe_spdm, addr, size, &val)) {
        return val;
    }

    return pci_default_read_config(pci_dev, addr, size);
}

static void ct3d_config_write(PCIDevice *pci_dev, uint32_t addr, uint32_t val,
                              int size)
{
    CXLType3Dev *ct3d = CXL_TYPE3(pci_dev);

    if (ct3d->spdm_port) {
        pcie_doe_write_config(&ct3d->doe_spdm, addr, val, size);
    }
    pcie_doe_write_config(&ct3d->doe_cdat, addr, val, size);
    pcie_doe_write_config(&ct3d->doe_comp, addr, val, size);
    pci_default_write_config(pci_dev, addr, val, size);
    pcie_aer_write_config(pci_dev, addr, val, size);
}

/*
 * Null value of all Fs suggested by IEEE RA guidelines for use of
 * EU, OUI and CID
 */
#define UI64_NULL ~(0ULL)

static void build_dvsecs(CXLType3Dev *ct3d)
{
    CXLComponentState *cxl_cstate = &ct3d->cxl_cstate;
    CXLDVSECRegisterLocator *regloc_dvsec;
    uint8_t *dvsec;
    int i;
    uint32_t range1_size_hi = 0, range1_size_lo = 0,
             range1_base_hi = 0, range1_base_lo = 0,
             range2_size_hi = 0, range2_size_lo = 0,
             range2_base_hi = 0, range2_base_lo = 0;

    /*
     * Volatile memory is mapped as (0x0)
     * Persistent memory is mapped at (volatile->size)
     */
    if (ct3d->hostvmem && ct3d->hostpmem) {
        range1_size_hi = ct3d->hostvmem->size >> 32;
        range1_size_lo = (2 << 5) | (2 << 2) | 0x3 |
                         (ct3d->hostvmem->size & 0xF0000000);
        range1_base_hi = 0;
        range1_base_lo = 0;
        range2_size_hi = ct3d->hostpmem->size >> 32;
        range2_size_lo = (2 << 5) | (2 << 2) | 0x3 |
                         (ct3d->hostpmem->size & 0xF0000000);
        range2_base_hi = ct3d->hostvmem->size >> 32;
        range2_base_lo = ct3d->hostvmem->size & 0xF0000000;
    } else {
        HostMemoryBackend *hmbe = ct3d->hostvmem ?
                                  ct3d->hostvmem : ct3d->hostpmem;
        range1_size_hi = hmbe->size >> 32;
        range1_size_lo = (2 << 5) | (2 << 2) | 0x3 |
                         (hmbe->size & 0xF0000000);
        range1_base_hi = 0;
        range1_base_lo = 0;
    }

    dvsec = (uint8_t *)&(CXLDVSECDevice){
        .cap = 0x1e,
        .ctrl = 0x2,
        .status2 = 0x2,
        .range1_size_hi = range1_size_hi,
        .range1_size_lo = range1_size_lo,
        .range1_base_hi = range1_base_hi,
        .range1_base_lo = range1_base_lo,
        .range2_size_hi = range2_size_hi,
        .range2_size_lo = range2_size_lo,
        .range2_base_hi = range2_base_hi,
        .range2_base_lo = range2_base_lo
    };
    cxl_component_create_dvsec(cxl_cstate, CXL2_TYPE3_DEVICE,
                               PCIE_CXL_DEVICE_DVSEC_LENGTH,
                               PCIE_CXL_DEVICE_DVSEC,
                               PCIE_CXL2_DEVICE_DVSEC_REVID, dvsec);

    regloc_dvsec = &(CXLDVSECRegisterLocator){
        .rsvd         = 0,
        .reg_base[0].lo = RBI_COMPONENT_REG | CXL_COMPONENT_REG_BAR_IDX,
        .reg_base[0].hi = 0,
        .reg_base[1].lo = RBI_CXL_DEVICE_REG | CXL_DEVICE_REG_BAR_IDX,
        .reg_base[1].hi = 0,
    };
    for (i = 0; i < CXL_NUM_CPMU_INSTANCES; i++) {
        regloc_dvsec->reg_base[2 + i].lo = CXL_CPMU_OFFSET(i) |
            RBI_CXL_CPMU_REG | CXL_DEVICE_REG_BAR_IDX;
        regloc_dvsec->reg_base[2 + i].hi = 0;
    }
    cxl_component_create_dvsec(cxl_cstate, CXL2_TYPE3_DEVICE,
                               REG_LOC_DVSEC_LENGTH, REG_LOC_DVSEC,
                               REG_LOC_DVSEC_REVID, (uint8_t *)regloc_dvsec);
    dvsec = (uint8_t *)&(CXLDVSECDeviceGPF){
        .phase2_duration = 0x603, /* 3 seconds */
        .phase2_power = 0x33, /* 0x33 miliwatts */
    };
    cxl_component_create_dvsec(cxl_cstate, CXL2_TYPE3_DEVICE,
                               GPF_DEVICE_DVSEC_LENGTH, GPF_DEVICE_DVSEC,
                               GPF_DEVICE_DVSEC_REVID, dvsec);
}

static void hdm_decoder_commit(CXLType3Dev *ct3d, int which)
{
    ComponentRegisters *cregs = &ct3d->cxl_cstate.crb;
    uint32_t *cache_mem = cregs->cache_mem_registers;

    assert(which == 0);

    /* TODO: Sanity checks that the decoder is possible */
    ARRAY_FIELD_DP32(cache_mem, CXL_HDM_DECODER0_CTRL, COMMIT, 0);
    ARRAY_FIELD_DP32(cache_mem, CXL_HDM_DECODER0_CTRL, ERR, 0);

    ARRAY_FIELD_DP32(cache_mem, CXL_HDM_DECODER0_CTRL, COMMITTED, 1);
}

static void ct3d_reg_write(void *opaque, hwaddr offset, uint64_t value,
                           unsigned size)
{
    CXLComponentState *cxl_cstate = opaque;
    ComponentRegisters *cregs = &cxl_cstate->crb;
    CXLType3Dev *ct3d = container_of(cxl_cstate, CXLType3Dev, cxl_cstate);
    uint32_t *cache_mem = cregs->cache_mem_registers;
    bool should_commit = false;
    int which_hdm = -1;

    assert(size == 4);
    g_assert(offset < CXL2_COMPONENT_CM_REGION_SIZE);

    switch (offset) {
    case A_CXL_HDM_DECODER0_CTRL:
        should_commit = FIELD_EX32(value, CXL_HDM_DECODER0_CTRL, COMMIT);
        which_hdm = 0;
        break;
    case A_CXL_RAS_UNC_ERR_STATUS:
    case A_CXL_RAS_COR_ERR_STATUS:
    {
        uint32_t rw1c = value;
        uint32_t temp = ldl_le_p((uint8_t *)cache_mem + offset);
        temp &= ~rw1c;
        stl_le_p((uint8_t *)cache_mem + offset, temp);
        return;
    }
    default:
        break;
    }

    stl_le_p((uint8_t *)cache_mem + offset, value);
    if (should_commit) {
        hdm_decoder_commit(ct3d, which_hdm);
    }
}

static bool cxl_setup_memory(CXLType3Dev *ct3d, Error **errp)
{
    DeviceState *ds = DEVICE(ct3d);
    MemoryRegion *mr;
    char *name;

    if (!ct3d->hostmem && !ct3d->hostvmem && !ct3d->hostpmem) {
        error_setg(errp, "at least one memdev property must be set");
        return false;
    } else if (ct3d->hostmem && ct3d->hostpmem) {
        error_setg(errp, "[memdev] cannot be used with new "
                         "[persistent-memdev] property");
        return false;
    } else if (ct3d->hostmem) {
        /* Use of hostmem property implies pmem */
        ct3d->hostpmem = ct3d->hostmem;
        ct3d->hostmem = NULL;
    }

    if (ct3d->hostpmem && !ct3d->lsa) {
        error_setg(errp, "lsa property must be set for persistent devices");
        return false;
    }

    if (ct3d->hostvmem) {
        mr = host_memory_backend_get_memory(ct3d->hostvmem);
        if (!mr) {
            error_setg(errp, "volatile memdev must have backing device");
            return false;
        }
        memory_region_set_nonvolatile(mr, false);
        memory_region_set_enabled(mr, true);
        host_memory_backend_set_mapped(ct3d->hostvmem, true);
        if (ds->id) {
            name = g_strdup_printf("cxl-type3-dpa-vmem-space:%s", ds->id);
        } else {
            name = g_strdup("cxl-type3-dpa-vmem-space");
        }
        address_space_init(&ct3d->hostvmem_as, mr, name);
        ct3d->cxl_dstate.vmem_size = mr->size;
        ct3d->cxl_dstate.mem_size += mr->size;
        g_free(name);
    }

    if (ct3d->hostpmem) {
        mr = host_memory_backend_get_memory(ct3d->hostpmem);
        if (!mr) {
            error_setg(errp, "persistent memdev must have backing device");
            return false;
        }
        memory_region_set_nonvolatile(mr, true);
        memory_region_set_enabled(mr, true);
        host_memory_backend_set_mapped(ct3d->hostpmem, true);
        if (ds->id) {
            name = g_strdup_printf("cxl-type3-dpa-pmem-space:%s", ds->id);
        } else {
            name = g_strdup("cxl-type3-dpa-pmem-space");
        }
        address_space_init(&ct3d->hostpmem_as, mr, name);
        ct3d->cxl_dstate.pmem_size = mr->size;
        ct3d->cxl_dstate.mem_size += mr->size;
        g_free(name);
    }

    return true;
}

static DOEProtocol doe_cdat_prot[] = {
    { CXL_VENDOR_ID, CXL_DOE_TABLE_ACCESS, cxl_doe_cdat_rsp },
    { }
};

static DOEProtocol doe_comp_prot[] = {
    {CXL_VENDOR_ID, CXL_DOE_COMPLIANCE, cxl_doe_compliance_rsp},
    { }
};

static DOEProtocol doe_spdm_prot[] = {
    { PCI_VENDOR_ID_PCI_SIG, PCI_SIG_DOE_CMA, pcie_doe_spdm_rsp },
    { PCI_VENDOR_ID_PCI_SIG, PCI_SIG_DOE_SECURED_CMA, pcie_doe_spdm_rsp },
    { }
};

static void ct3_realize(PCIDevice *pci_dev, Error **errp)
{
    CXLType3Dev *ct3d = CXL_TYPE3(pci_dev);
    CXLComponentState *cxl_cstate = &ct3d->cxl_cstate;
    ComponentRegisters *regs = &cxl_cstate->crb;
    MemoryRegion *mr = &regs->component_registers;
    uint8_t *pci_conf = pci_dev->config;
    unsigned short msix_num = 4;
    int i, rc;

    if (!cxl_setup_memory(ct3d, errp)) {
        return;
    }

    pci_config_set_prog_interface(pci_conf, 0x10);

    pcie_endpoint_cap_init(pci_dev, 0x80);
    if (ct3d->sn != UI64_NULL) {
        pcie_dev_ser_num_init(pci_dev, 0x100, ct3d->sn);
        cxl_cstate->dvsec_offset = 0x100 + 0x0c;
    } else {
        cxl_cstate->dvsec_offset = 0x100;
    }

    ct3d->cxl_cstate.pdev = pci_dev;
    build_dvsecs(ct3d);

    regs->special_ops = g_new0(MemoryRegionOps, 1);
    if (!regs->special_ops) {
        goto err_address_space_free;
    }
    regs->special_ops->write = ct3d_reg_write;

    cxl_component_register_block_init(OBJECT(pci_dev), cxl_cstate,
                                      TYPE_CXL_TYPE3);

    pci_register_bar(
        pci_dev, CXL_COMPONENT_REG_BAR_IDX,
        PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64, mr);

    cxl_device_register_block_init(OBJECT(pci_dev), &ct3d->cxl_dstate);
    cxl_cpmu_register_block_init(OBJECT(pci_dev), &ct3d->cxl_dstate, 0, 3);
    cxl_cpmu_register_block_init(OBJECT(pci_dev), &ct3d->cxl_dstate, 1, 3);
    pci_register_bar(pci_dev, CXL_DEVICE_REG_BAR_IDX,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                         PCI_BASE_ADDRESS_MEM_TYPE_64,
                     &ct3d->cxl_dstate.device_registers);

    /* MSI(-X) Initailization */
    msix_init_exclusive_bar(pci_dev, msix_num, 4, NULL);
    for (i = 0; i < msix_num; i++) {
        msix_vector_use(pci_dev, i);
    }

    /* DOE Initailization */
    pcie_doe_init(pci_dev, &ct3d->doe_cdat, 0x190, doe_cdat_prot, true, 0);

    cxl_cstate->cdat.build_cdat_table = ct3_build_cdat_table;
    cxl_cstate->cdat.free_cdat_table = ct3_free_cdat_table;
    cxl_cstate->cdat.private = ct3d;
    cxl_doe_cdat_init(cxl_cstate, errp);
    pcie_doe_init(pci_dev, &ct3d->doe_comp, 0x1b0, doe_comp_prot, true, 1);
    if (ct3d->spdm_port) {
        pcie_doe_init(pci_dev, &ct3d->doe_spdm, 0x1d0, doe_spdm_prot, true, 2);
        ct3d->doe_spdm.socket = spdm_sock_init(ct3d->spdm_port, errp);
        if (ct3d->doe_spdm.socket < 0) {
            goto err_free_special_ops;
        }
    }
    pcie_cap_deverr_init(pci_dev);
    /* Leave a bit of room for expansion */
    rc = pcie_aer_init(pci_dev, PCI_ERR_VER, 0x200, PCI_ERR_SIZEOF, NULL);
    if (rc) {
        goto err_free_spdm_socket;
    }
    /* CXL RAS uses AER correct INTERNAL erorrs - so enable by default */
    pci_set_long(pci_dev->config + 0x200 + PCI_ERR_COR_MASK,
                 PCI_ERR_COR_MASK_DEFAULT & ~PCI_ERR_COR_INTERNAL);
    cxl_event_init(&ct3d->cxl_dstate);
    return;

err_free_spdm_socket:
    spdm_sock_fini(ct3d->doe_spdm.socket);
    cxl_doe_cdat_release(cxl_cstate);
err_free_special_ops:
    g_free(regs->special_ops);
err_address_space_free:
    if (ct3d->hostvmem) {
        address_space_destroy(&ct3d->hostvmem_as);
    }
    if (ct3d->hostpmem) {
        address_space_destroy(&ct3d->hostpmem_as);
    }
    return;
}

static void ct3_exit(PCIDevice *pci_dev)
{
    CXLType3Dev *ct3d = CXL_TYPE3(pci_dev);
    CXLComponentState *cxl_cstate = &ct3d->cxl_cstate;
    ComponentRegisters *regs = &cxl_cstate->crb;

    pcie_aer_exit(pci_dev);
    cxl_doe_cdat_release(cxl_cstate);
    spdm_sock_fini(ct3d->doe_spdm.socket);
    g_free(regs->special_ops);
    if (ct3d->hostvmem) {
        address_space_destroy(&ct3d->hostvmem_as);
    }
    if (ct3d->hostpmem) {
        address_space_destroy(&ct3d->hostpmem_as);
    }
}

/* TODO: Support multiple HDM decoders and DPA skip */
static bool cxl_type3_dpa(CXLType3Dev *ct3d, hwaddr host_addr, uint64_t *dpa)
{
    uint32_t *cache_mem = ct3d->cxl_cstate.crb.cache_mem_registers;
    uint64_t decoder_base, decoder_size, hpa_offset;
    uint32_t hdm0_ctrl;
    int ig, iw;

    decoder_base = (((uint64_t)cache_mem[R_CXL_HDM_DECODER0_BASE_HI] << 32) |
                    cache_mem[R_CXL_HDM_DECODER0_BASE_LO]);
    if ((uint64_t)host_addr < decoder_base) {
        return false;
    }

    hpa_offset = (uint64_t)host_addr - decoder_base;

    decoder_size = ((uint64_t)cache_mem[R_CXL_HDM_DECODER0_SIZE_HI] << 32) |
        cache_mem[R_CXL_HDM_DECODER0_SIZE_LO];
    if (hpa_offset >= decoder_size) {
        return false;
    }

    hdm0_ctrl = cache_mem[R_CXL_HDM_DECODER0_CTRL];
    iw = FIELD_EX32(hdm0_ctrl, CXL_HDM_DECODER0_CTRL, IW);
    ig = FIELD_EX32(hdm0_ctrl, CXL_HDM_DECODER0_CTRL, IG);

    *dpa = (MAKE_64BIT_MASK(0, 8 + ig) & hpa_offset) |
        ((MAKE_64BIT_MASK(8 + ig + iw, 64 - 8 - ig - iw) & hpa_offset) >> iw);

    return true;
}

MemTxResult cxl_type3_read(PCIDevice *d, hwaddr host_addr, uint64_t *data,
                           unsigned size, MemTxAttrs attrs)
{
    CXLType3Dev *ct3d = CXL_TYPE3(d);
    uint64_t dpa_offset;
    MemoryRegion *vmr = NULL, *pmr = NULL;
    AddressSpace *as;

    if (ct3d->hostvmem) {
        vmr = host_memory_backend_get_memory(ct3d->hostvmem);
    }
    if (ct3d->hostpmem) {
        pmr = host_memory_backend_get_memory(ct3d->hostpmem);
    }

    if (!vmr && !pmr) {
        return MEMTX_ERROR;
    }

    if (!cxl_type3_dpa(ct3d, host_addr, &dpa_offset)) {
        return MEMTX_ERROR;
    }

    if (dpa_offset > int128_get64(ct3d->cxl_dstate.mem_size)) {
        return MEMTX_ERROR;
    }

    as = (vmr && (dpa_offset <= int128_get64(vmr->size))) ?
         &ct3d->hostvmem_as : &ct3d->hostpmem_as;
    return address_space_read(as, dpa_offset, attrs, data, size);
}

MemTxResult cxl_type3_write(PCIDevice *d, hwaddr host_addr, uint64_t data,
                            unsigned size, MemTxAttrs attrs)
{
    CXLType3Dev *ct3d = CXL_TYPE3(d);
    uint64_t dpa_offset;
    MemoryRegion *vmr = NULL, *pmr = NULL;
    AddressSpace *as;

    if (ct3d->hostvmem) {
        vmr = host_memory_backend_get_memory(ct3d->hostvmem);
    }
    if (ct3d->hostpmem) {
        pmr = host_memory_backend_get_memory(ct3d->hostpmem);
    }

    if (!vmr && !pmr) {
        return MEMTX_OK;
    }

    if (!cxl_type3_dpa(ct3d, host_addr, &dpa_offset)) {
        return MEMTX_OK;
    }

    if (dpa_offset > int128_get64(ct3d->cxl_dstate.mem_size)) {
        return MEMTX_OK;
    }

    as = (vmr && (dpa_offset <= int128_get64(vmr->size))) ?
         &ct3d->hostvmem_as : &ct3d->hostpmem_as;
    return address_space_write(as, dpa_offset, attrs, &data, size);
}

static void ct3d_reset(DeviceState *dev)
{
    CXLType3Dev *ct3d = CXL_TYPE3(dev);
    uint32_t *reg_state = ct3d->cxl_cstate.crb.cache_mem_registers;
    uint32_t *write_msk = ct3d->cxl_cstate.crb.cache_mem_regs_write_mask;

    cxl_component_register_init_common(reg_state, write_msk, CXL2_TYPE3_DEVICE);
    cxl_device_register_init_common(&ct3d->cxl_dstate);
}

static Property ct3_props[] = {
    DEFINE_PROP_LINK("memdev", CXLType3Dev, hostmem, TYPE_MEMORY_BACKEND,
                     HostMemoryBackend *), /* for backward compatibility */
    DEFINE_PROP_LINK("persistent-memdev", CXLType3Dev, hostpmem,
                     TYPE_MEMORY_BACKEND, HostMemoryBackend *),
    DEFINE_PROP_LINK("volatile-memdev", CXLType3Dev, hostvmem,
                     TYPE_MEMORY_BACKEND, HostMemoryBackend *),
    DEFINE_PROP_LINK("lsa", CXLType3Dev, lsa, TYPE_MEMORY_BACKEND,
                     HostMemoryBackend *),
    DEFINE_PROP_UINT64("sn", CXLType3Dev, sn, UI64_NULL),
    DEFINE_PROP_STRING("cdat", CXLType3Dev, cxl_cstate.cdat.filename),
    DEFINE_PROP_UINT16("spdm", CXLType3Dev, spdm_port, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static uint64_t get_lsa_size(CXLType3Dev *ct3d)
{
    MemoryRegion *mr = NULL;
    if (ct3d->lsa) {
        mr = host_memory_backend_get_memory(ct3d->lsa);
        return memory_region_size(mr);
    }
    return 0;
}

static void validate_lsa_access(MemoryRegion *mr, uint64_t size,
                                uint64_t offset)
{
    assert(offset + size <= memory_region_size(mr));
    assert(offset + size > offset);
}

static uint64_t get_lsa(CXLType3Dev *ct3d, void *buf, uint64_t size,
                    uint64_t offset)
{
    MemoryRegion *mr = NULL;
    void *lsa;

    if (ct3d->lsa) {
        mr = host_memory_backend_get_memory(ct3d->lsa);
        validate_lsa_access(mr, size, offset);

        lsa = memory_region_get_ram_ptr(mr) + offset;
        memcpy(buf, lsa, size);
        return size;
    }

    return 0;
}

static void set_lsa(CXLType3Dev *ct3d, const void *buf, uint64_t size,
                    uint64_t offset)
{
    MemoryRegion *mr = NULL;
    void *lsa = NULL;

    if (ct3d->lsa) {
        mr = host_memory_backend_get_memory(ct3d->lsa);
        validate_lsa_access(mr, size, offset);

        lsa = memory_region_get_ram_ptr(mr) + offset;
        memcpy(lsa, buf, size);
        memory_region_set_dirty(mr, offset, size);
    }

    /*
     * Just like the PMEM, if the guest is not allowed to exit gracefully, label
     * updates will get lost.
     */
}

static CXLPoisonList *get_poison_list(CXLType3Dev *ct3d)
{
    /* This will get more complex  - for now it's a bit pointless */
    return &ct3d->poison_list;
}

void qmp_cxl_inject_poison(const char *path, uint64_t start, uint64_t length,
                           Error **errp)
{
    Object *obj = object_resolve_path(path, NULL);
    CXLType3Dev *ct3d;
    CXLPoison *p;

    if (!obj) {
        error_setg(errp, "Unable to resolve path");
        return;
    }
    if (!object_dynamic_cast(obj, TYPE_CXL_TYPE3)) {
        error_setg(errp, "Path does not point to a CXL type 3 device");
    }
    ct3d = CXL_TYPE3(obj);
    p = g_new0(CXLPoison, 1);
    if (!p) {
        return;
    }
    p->length = length;
    p->start = start;

    QLIST_INSERT_HEAD(&ct3d->poison_list, p, node);
}

void qmp_cxl_inject_uncorrectable_error(const char *path,
                                        CxlUncorErrorType type,
                                        uint32List *header, Error **errp)
{
    static PCIEAERErr err = {};
    Object *obj = object_resolve_path(path, NULL);
    CXLType3Dev *ct3d;
    uint32_t *reg_state;
    uint8_t header_count = 0;
    uint32_t unc_err;

    if (!obj) {
        error_setg(errp, "Unable to resolve path");
        return;
    }
    if (!object_dynamic_cast(obj, TYPE_CXL_TYPE3)) {
        error_setg(errp, "Path does not point to a CXL type 3 device");
    }

    err.status = PCI_ERR_UNC_INTN;
    err.source_id = pci_requester_id(PCI_DEVICE(obj));
    err.flags = 0;

    ct3d = CXL_TYPE3(obj);
    reg_state = ct3d->cxl_cstate.crb.cache_mem_registers;
    unc_err = reg_state[R_CXL_RAS_UNC_ERR_STATUS];
    switch (type) {
    case CXL_UNCOR_ERROR_TYPE_CACHE_DATA_PARITY:
        unc_err |= (1 << 0);
        break;
    case CXL_UNCOR_ERROR_TYPE_CACHE_ADDRESS_PARITY:
        unc_err |= (1 << 1);
        break;
    case CXL_UNCOR_ERROR_TYPE_CACHE_BE_PARITY:
        unc_err |= (1 << 2);
        break;
    case CXL_UNCOR_ERROR_TYPE_CACHE_DATA_ECC:
        unc_err |= (1 << 3);
        break;
    case CXL_UNCOR_ERROR_TYPE_MEM_DATA_PARITY:
        unc_err |= (1 << 4);
        break;
    case CXL_UNCOR_ERROR_TYPE_MEM_ADDRESS_PARITY:
        unc_err |= (1 << 5);
        break;
    case CXL_UNCOR_ERROR_TYPE_MEM_BE_PARITY:
        unc_err |= (1 << 6);
        break;
    case CXL_UNCOR_ERROR_TYPE_MEM_DATA_ECC:
        unc_err |= (1 << 7);
        break;
    case CXL_UNCOR_ERROR_TYPE_REINIT_THRESHOLD:
        unc_err |= (1 << 8);
        break;
    case CXL_UNCOR_ERROR_TYPE_RSVD_ENCODING:
        unc_err |= (1 << 9);
        break;
    case CXL_UNCOR_ERROR_TYPE_POISON_RECEIVED:
        unc_err |= (1 << 10);
        break;
    case CXL_UNCOR_ERROR_TYPE_RECEIVER_OVERFLOW:
        unc_err |= (1 << 11);
        break;
    case CXL_UNCOR_ERROR_TYPE_INTERNAL:
        unc_err |= (1 << 14);
        break;
    case CXL_UNCOR_ERROR_TYPE_CXL_IDE_TX:
        unc_err |= (1 << 15);
        break;
    case CXL_UNCOR_ERROR_TYPE_CXL_IDE_RX:
        unc_err |= (1 << 16);
        break;
    default:
        error_setg(errp, "Unhandled error injection type");
        return;
    }
    reg_state[R_CXL_RAS_UNC_ERR_STATUS] = unc_err;
    while (header && header_count < 32) {
        reg_state[R_CXL_RAS_ERR_HEADER0 + header_count++] = header->value;

        header = header->next;
    }
    if (header_count > 32) {
        error_setg(errp, "Header must be 32 DWORD or less");
        return;
    }

    pcie_aer_inject_error(PCI_DEVICE(obj), &err);
}

void qmp_cxl_inject_correctable_error(const char *path, CxlCorErrorType type,
                                      uint32List *header, Error **errp)
{
    static PCIEAERErr err = {};
    Object *obj = object_resolve_path(path, NULL);
    CXLType3Dev *ct3d;
    uint32_t *reg_state;
    uint8_t header_count = 0;
    uint32_t cor_err;

    if (!obj) {
        error_setg(errp, "Unable to resolve path");
        return;
    }
    if (!object_dynamic_cast(obj, TYPE_CXL_TYPE3)) {
        error_setg(errp, "Path does not point to a CXL type 3 device");
    }

    err.status = PCI_ERR_COR_INTERNAL;
    err.source_id = pci_requester_id(PCI_DEVICE(obj));
    err.flags = PCIE_AER_ERR_IS_CORRECTABLE;

    ct3d = CXL_TYPE3(obj);
    reg_state = ct3d->cxl_cstate.crb.cache_mem_registers;
    cor_err = reg_state[R_CXL_RAS_COR_ERR_STATUS];
    switch (type) {
    case CXL_COR_ERROR_TYPE_CACHE_DATA_ECC:
        cor_err |= (1 << 0);
        break;
    case CXL_COR_ERROR_TYPE_MEM_DATA_ECC:
        cor_err |= (1 << 1);
        break;
    case CXL_COR_ERROR_TYPE_CRC_THRESHOLD:
        cor_err |= (1 << 2);
        break;
    case CXL_COR_ERROR_TYPE_RETRY_THRESHOLD:
        cor_err |= (1 << 3);
        break;
    case CXL_COR_ERROR_TYPE_CACHE_POISON_RECEIVED:
        cor_err |= (1 << 4);
        break;
    case CXL_COR_ERROR_TYPE_MEM_POISON_RECEIVED:
        cor_err |= (1 << 5);
        break;
    case CXL_COR_ERROR_TYPE_PHYSICAL:
        cor_err |= (1 << 6);
        break;
    default:
        error_setg(errp, "Unhandled error injection type");
        return;
    }
    reg_state[R_CXL_RAS_COR_ERR_STATUS] = cor_err;
    while (header && header_count < 32) {
        reg_state[R_CXL_RAS_ERR_HEADER0 + header_count++] = header->value;

        header = header->next;
    }
    if (header_count > 32) {
        error_setg(errp, "Header must be 32 DWORD or less");
        return;
    }

    pcie_aer_inject_error(PCI_DEVICE(obj), &err);
}

static void ct3_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);
    CXLType3Class *cvc = CXL_TYPE3_CLASS(oc);

    pc->realize = ct3_realize;
    pc->exit = ct3_exit;
    pc->class_id = PCI_CLASS_MEMORY_CXL;
    pc->vendor_id = PCI_VENDOR_ID_INTEL;
    pc->device_id = 0xd93; /* LVF for now */
    pc->revision = 1;

    pc->config_write = ct3d_config_write;
    pc->config_read = ct3d_config_read;

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "CXL Memory Device (Type 3)";
    dc->reset = ct3d_reset;
    device_class_set_props(dc, ct3_props);

    cvc->get_lsa_size = get_lsa_size;
    cvc->get_lsa = get_lsa;
    cvc->set_lsa = set_lsa;
    cvc->get_poison_list = get_poison_list;

}

static const TypeInfo ct3d_info = {
    .name = TYPE_CXL_TYPE3,
    .parent = TYPE_PCI_DEVICE,
    .class_size = sizeof(struct CXLType3Class),
    .class_init = ct3_class_init,
    .instance_size = sizeof(CXLType3Dev),
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_CXL_DEVICE },
        { INTERFACE_PCIE_DEVICE },
        {}
    },
};

static void ct3d_registers(void)
{
    type_register_static(&ct3d_info);
}

type_init(ct3d_registers);
