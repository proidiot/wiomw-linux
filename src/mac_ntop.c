#include <config.h>
#include "mac_ntop.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

char* mac_ntop(const unsigned char* src, char* dst, size_t srclen)
{
	if (srclen != 6) {
		return (char*)NULL;
	} else {
		sprintf(dst, "%02X:%02X:%02X:%02X:%02X:%02X", src[0], src[1], src[2], src[3], src[4], src[5]);
	}
	return dst;
}

