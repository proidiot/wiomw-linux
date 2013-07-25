#include <config.h>
#include "mac_ntop.h"
#include <stdio.h>
#include <stdlib.h>

char* mac_ntop(const unsigned char* src, char* dst, size_t srclen)
{
	if (srclen != 6) {
		return (char*)NULL;
	} else if (htons(0x026A) == 0x026A) {
		sprintf(dst, "%2x:%2x:%2x:%2x:%2x:%2x", src[0], src[1], src[2], src[3], src[4], src[5]);
	} else {
		sprintf(dst, "%2x:%2x:%2x:%2x:%2x:%2x", src[5], src[4], src[3], src[2], src[1], src[0]);
	}
	return dst;
}

