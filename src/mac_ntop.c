/**
 * Copyright 2013, 2014 Who Is On My WiFi.
 *
 * This file is part of Who Is On My WiFi Linux.
 *
 * Who Is On My WiFi Linux is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Who Is On My WiFi Linux is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Who Is On My WiFi Linux.  If not, see <http://www.gnu.org/licenses/>.
 *
 * More information about Who Is On My WiFi Linux can be found at
 * <http://www.whoisonmywifi.com/>.
 */

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

