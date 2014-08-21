#ifndef _WIOMW_MNL_HELPERS_H_
#define _WIOMW_MNL_HELPERS_H_

#include <libmnl/libmnl.h>
#include "ip.h"

int mnl_attr_copy_binary(void* dst, const struct nlattr* nl_attr, const size_t binlen);
int mnl_attr_copy_union_ip(union ip* addr, const struct nlattr* nl_attr, const unsigned char af);

#endif
