
#include "qemu/osdep.h"
#include "qapi/qapi-commands-cxl.h"

void qmp_cxl_inject_poison(const char * path, uint64_t start, uint64_t length,
                           Error **errp) {}
