/*
 * CXL host parameter parsing routine stubs
 *
 * Copyright (c) 2022 Huawei
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/cxl/cxl.h"
#include "hw/cxl/cxl_host.h"

void cxl_fmws_link_targets(CXLState *stat, Error **errp) {};
void cxl_machine_init(Object *obj, CXLState *state) {};
void cxl_hook_up_pxb_registers(PCIBus *bus, CXLState *state, Error **errp) {};

void hmp_cxl_event_inject(Monitor *mon, const QDict *qdict)
{
    monitor_printf(mon, "CXL devices not supported\n");
}

const MemoryRegionOps cfmws_ops;
