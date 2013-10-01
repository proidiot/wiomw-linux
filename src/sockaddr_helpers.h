#ifndef _WIOMW_SOCKADDR_HELPERS_H_
#define _WIOMW_SOCKADDR_HELPERS_H_

#include <stdint.h>
#include <sys/socket.h>

typedef struct _network_list_struct {
	struct sockaddr* addr_base;
	uint8_t prefix;
	struct _network_list_struct* next;
} * network_list_t;

void add_network(network_list_t* list, struct sockaddr* addr_base, uint8_t prefix);

void destroy_network_list(network_list_t* list);


int increment_addr(struct sockaddr* addr_base, uint8_t prefix, struct sockaddr* addr_to_increment);

int check_addr_range(struct sockaddr* addr_base, uint8_t prefix, struct sockaddr* addr_to_check);

int check_autoscannable_range(struct sockaddr* addr, uint8_t prefix);


network_list_t get_overlapping_networks(struct sockaddr* addr_base, uint8_t prefix, network_list_t list);

#endif
