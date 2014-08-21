#include <config.h>
#include "mnl_helpers.h"

#include <libmnl/libmnl.h>
#include <string.h>

int mnl_attr_copy_binary(void* dst, const struct nlattr* nl_attr, const size_t binlen)
{
	int result = 0;
	if ((result = mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, binlen)) >= 0) {
		memcpy(dst, mnl_attr_get_payload(nl_attr), binlen);
	}
	return result;
}

int mnl_attr_copy_union_ip(union ip* addr, const struct nlattr* nl_attr, const unsigned char af)
{
	if (af == AF_INET) {
		return mnl_attr_copy_binary(&addr->ip4, nl_attr, sizeof(struct in_addr));
	} else if (af == AF_INET6) {
		return mnl_attr_copy_binary(&addr->ip6, nl_attr, sizeof(struct in6_addr));
	} else {
		return -1;
	}
}

