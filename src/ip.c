#include <config.h>
#include "ip.h"
#include <stdio.h>
#include "string_helpers.h"

void snprint_ip(char* const buffer, const size_t buflen, const int af, const union ip addr)
{
	if (af == AF_INET) {
		inet_ntop(af, &(addr.ip4), buffer, buflen);
	} else if (af == AF_INET6) {
		inet_ntop(af, &(addr.ip6), buffer, buflen);
	}
}

char* stpnprint_ip_dump(char* const buffer, const size_t buflen, const union ip addr)
{
	return stpnprintf(
			buffer,
			buflen,
			"%2X%2X%2X%2X%2X%2X%2X%2X%2X%2X%2X%2X%2X%2X%2X%2X",
			((unsigned char*)&addr)[0],
			((unsigned char*)&addr)[1],
			((unsigned char*)&addr)[2],
			((unsigned char*)&addr)[3],
			((unsigned char*)&addr)[4],
			((unsigned char*)&addr)[5],
			((unsigned char*)&addr)[6],
			((unsigned char*)&addr)[7],
			((unsigned char*)&addr)[8],
			((unsigned char*)&addr)[9],
			((unsigned char*)&addr)[10],
			((unsigned char*)&addr)[11],
			((unsigned char*)&addr)[12],
			((unsigned char*)&addr)[13],
			((unsigned char*)&addr)[14],
			((unsigned char*)&addr)[15]);
}

