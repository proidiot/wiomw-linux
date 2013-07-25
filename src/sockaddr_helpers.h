#ifndef _WIOMW_SOCKADDR_HELPERS_H_
#define _WIOMW_SOCKADDR_HELPERS_H_

#include <stdint.h>
#include <sys/socket.h>

int increment_addr(struct sockaddr* addr_base, uint8_t prefix, struct sockaddr* addr_to_increment);

int check_addr_range(struct sockaddr* addr_base, uint8_t prefix, struct sockaddr* addr_to_check);

int check_scannable_range(struct sockaddr* addr, uint8_t prefix);

#endif
