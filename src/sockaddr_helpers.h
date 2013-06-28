#ifndef _WIOMW_SOCKADDR_HELPERS_H_
#define _WIOMW_SOCKADDR_HELPERS_H_

#include <stdint.h>
#include <sys/socket.h>

int increment_addr(
		struct sockaddr* addr_base,
		socklen_t size_base,
		uint8_t prefix,
		struct sockaddr* addr_to_increment,
		socklen_t size_sock);

int check_addr_range(
		struct sockaddr* addr_base,
		socklen_t size_base,
		uint8_t prefix,
		struct sockaddr* addr_to_check,
		socklen_t size_sock);

int check_scannable_range(struct sockaddr* addr, socklen_t slen, uint8_t prefix);

#endif
