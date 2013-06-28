#include <config.h>
#include "sockaddr_helpers.h"
#include "print_error.h"
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

int increment_addr(
		struct sockaddr* addr_base,
		socklen_t size_base,
		uint8_t prefix,
		struct sockaddr* addr_to_increment,
		socklen_t size_sock)
{
	if (addr_base == NULL) {
		return -1;
	} else if (size_base == 0) {
		return -2;
	} else if (addr_to_increment == NULL) {
		return -3;
	} else if (size_sock < size_base) {
		return -4;
	} else if (addr_base->sa_family != AF_INET && addr_base->sa_family != AF_INET6) {
		return -5;
	} else if (prefix > 32 && addr_base->sa_family == AF_INET) {
		return -6;
	} else if (prefix > 128 && addr_base->sa_family == AF_INET6) {
		return -7;
	} else if (prefix == 32 && addr_base->sa_family == AF_INET) {
		return -8;
	} else if (prefix == 128 && addr_base->sa_family == AF_INET6) {
		return -9;
	} else if (prefix == 0 && addr_base->sa_family == AF_INET) {
		print_error("Full rage IP enumeration is currently not allowed");
		return -999;
	} else if (prefix == 0 && addr_base->sa_family == AF_INET6) {
		print_error("Full rage IP enumeration is currently not allowed");
		return -999;
	} else if (addr_base->sa_family == AF_INET) {
		struct sockaddr_in* base = (struct sockaddr_in*)addr_base;
		struct sockaddr_in* addr = (struct sockaddr_in*)addr_to_increment;
		uint8_t suffix = 32 - prefix;
		unsigned long base_ip = (ntohl(base->sin_addr.s_addr) >> suffix) << suffix;
		unsigned long bcast_ip = (((ntohl(base->sin_addr.s_addr) >> suffix) + 1) << suffix) - 1;
		unsigned long ip = ntohl(addr->sin_addr.s_addr);

		if (ip == 0) {
			ip = base_ip + 1;
		} else if (ip > base_ip && ip < bcast_ip) {
			ip++;
		} else {
			return -10;
		}

		addr->sin_family = AF_INET;
		addr->sin_addr.s_addr = htonl(ip);

		return bcast_ip - ip;
	} else {
		/* TODO: fixme */
		print_error("The code for IPv6 enumeration has not yet been completed");
		return -999;
	}
}

int check_addr_range(
		struct sockaddr* addr_base,
		socklen_t size_base,
		uint8_t prefix,
		struct sockaddr* addr_to_check,
		socklen_t size_sock)
{
	if (addr_base == NULL) {
		return -1;
	} else if (size_base == 0) {
		return -2;
	} else if (addr_to_check == NULL) {
		return -3;
	} else if (size_sock == 0) {
		return -4;
	} else if (addr_base->sa_family != AF_INET && addr_base->sa_family != AF_INET6) {
		return -5;
	} else if (addr_base->sa_family != addr_to_check->sa_family) {
		return -8;
	} else if (prefix > 32 && addr_base->sa_family == AF_INET) {
		return -6;
	} else if (prefix > 128 && addr_base->sa_family == AF_INET6) {
		return -7;
	} else if (addr_base->sa_family != addr_to_check->sa_family) {
		return -8;
	} else if (prefix == 32 && addr_base->sa_family == AF_INET) {
		return ((struct sockaddr_in*)addr_base)->sin_addr.s_addr == ((struct sockaddr_in*)addr_to_check)->sin_addr.s_addr;
	} else if (prefix == 128 && addr_base->sa_family == AF_INET6) {
		/* TODO: fixme */
		print_error("The code for IPv6 comparison has not yet been completed");
		return -999;
	} else if (prefix == 0) {
		return (1==1);
	} else if (addr_base->sa_family == AF_INET) {
		struct sockaddr_in* base = (struct sockaddr_in*)addr_base;
		struct sockaddr_in* addr = (struct sockaddr_in*)addr_to_check;
		uint8_t suffix = 32 - prefix;
		unsigned long base_ip = (ntohl(base->sin_addr.s_addr) >> suffix) << suffix;
		unsigned long bcast_ip = (((ntohl(base->sin_addr.s_addr) >> suffix) + 1) << suffix) - 1;
		unsigned long ip = ntohl(addr->sin_addr.s_addr);

		if (ip > base_ip && ip < bcast_ip) {
			return (1==1);
		} else {
			return (1==0);
		}
	} else {
		/* TODO: fixme */
		print_error("The code for IPv6 comparison has not yet been completed");
		return -999;
	}
}

int check_scannable_range(struct sockaddr* addr, socklen_t slen, uint8_t prefix)
{
	if (addr == NULL) {
		return -1;
	} else if (slen == 0) {
		return -2;
	} else if (addr->sa_family == AF_INET) {
		struct sockaddr_in safe_addr;
		socklen_t safe_len = sizeof(struct sockaddr_in);
		memset(&safe_addr, 0, safe_len);
		safe_addr.sin_family = AF_INET;

		inet_pton(AF_INET, "10.0.0.0", &safe_addr.sin_addr.s_addr);
		if (check_addr_range((struct sockaddr*)&safe_addr, safe_len, 8, addr, slen) && prefix >= 8) {
			return (1==1);
		}

		inet_pton(AF_INET, "172.16.0.0", &safe_addr.sin_addr.s_addr);
		if (check_addr_range((struct sockaddr*)&safe_addr, safe_len, 12, addr, slen) && prefix >= 12) {
			return (1==1);
		}

		inet_pton(AF_INET, "192.168.0.0", &safe_addr.sin_addr.s_addr);
		if (check_addr_range((struct sockaddr*)&safe_addr, safe_len, 16, addr, slen) && prefix >= 16) {
			return (1==1);
		}

		return (1==0);
	} else if (addr->sa_family == AF_INET6) {
		/* TODO: fixme */
		print_error("The code for IPv6 acceptable range checking has not yet been completed");
		return -999;
	} else {
		print_error("Unable to check if address is within an acceptable range: Unknown address family");
		return -1;
	}
}

