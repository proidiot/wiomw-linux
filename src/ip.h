#ifndef _WIOMW_IP_H_
#define _WIOMW_IP_H_

#include <arpa/inet.h>

union ip {
	struct in6_addr ip6;
	struct in_addr ip4;
};

void snprint_ip(char* const buffer, const size_t buflen, const int af, const union ip);
char* stpnprint_ip_dump(char* const buffer, const size_t buflen, const union ip);

#define STPNPRINT_IP_DUMP_LEN 32

#endif
