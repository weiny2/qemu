
#include "qemu/osdep.h"
#include "qapi/qapi-commands-cxl.h"

void qmp_cxl_inject_gen_media_event(const char *path, uint8_t log_type,
                                    uint8_t flags, uint64_t phys_addr,
				    Error **errp) {}
void qmp_cxl_inject_poison(const char *path, uint64_t start, uint64_t length,
                           Error **errp) {}
void qmp_cxl_inject_uncorrectable_error(const char *path,
                                        CxlUncorErrorType type,
                                        uint32List *header, Error **errp) {}

void qmp_cxl_inject_correctable_error(const char *path, CxlCorErrorType type,
                                      uint32List *header, Error **errp) {}
