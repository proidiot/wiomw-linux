#include <config.h>
#include "sockaddr_helpers.h"
#include "print_error.h"
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <sysexits.h>


void add_network(network_list_t* list, struct sockaddr* addr_base, uint8_t prefix)
{
	network_list_t temp = (network_list_t)malloc(sizeof(struct _network_list_struct));
	if (temp == NULL) {
		print_syserror("Unable to allocate more memory for network list");
		exit(EX_OSERR);
	}

	temp->addr_base = addr_base;
	temp->prefix = prefix;
	temp->next = NULL;

	if (*list == NULL) {
		*list = temp;
	} else {
		network_list_t list_iterator = *list;

		while (list_iterator->next != NULL) {
			list_iterator = list_iterator->next;
		}

		list_iterator->next = temp;
	}
}

void destroy_network_list(network_list_t* list)
{
	while (*list != NULL) {
		network_list_t temp = *list;
		*list = temp->next;
		free(temp);
	}
}


int increment_addr(struct sockaddr* addr_base, uint8_t prefix, struct sockaddr* addr_to_increment)
{
	if (addr_base == NULL) {
		return -1;
	} else if (addr_to_increment == NULL) {
		return -3;
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
		print_error("Full range IP enumeration is not allowed");
		return -999;
	} else if (prefix == 0 && addr_base->sa_family == AF_INET6) {
		print_error("Full range IP enumeration is not allowed");
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
	} else if (addr_base->sa_family == AF_INET6) {
		/* TODO: fixme */
		print_error("The code for IPv6 enumeration has not yet been completed");
		return -999;
	} else {
		print_error("Unknown address family for base address");
		return -999;
	}
}

int check_addr_range(struct sockaddr* addr_base, uint8_t prefix, struct sockaddr* addr_to_check)
{
	if (addr_base == NULL) {
		return -1;
	} else if (addr_to_check == NULL) {
		return -3;
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
	} else if (addr_base->sa_family == AF_INET6) {
		/* TODO: fixme */
		print_error("The code for IPv6 comparison has not yet been completed");
		return -999;
	} else {
		print_error("Unknown address family for base address");
		return -999;
	}
}

int check_autoscannable_range(struct sockaddr* addr, uint8_t prefix)
{
	if (addr == NULL) {
		return -1;
	} else if (addr->sa_family == AF_INET) {
		struct sockaddr_in safe_addr;
		socklen_t safe_len = sizeof(struct sockaddr_in);
		memset(&safe_addr, 0, safe_len);
		safe_addr.sin_family = AF_INET;

		inet_pton(AF_INET, "10.0.0.0", &safe_addr.sin_addr.s_addr);
		if (check_addr_range((struct sockaddr*)&safe_addr, 8, addr) && prefix >= 8) {
			return (1==1);
		}

		inet_pton(AF_INET, "172.16.0.0", &safe_addr.sin_addr.s_addr);
		if (check_addr_range((struct sockaddr*)&safe_addr, 12, addr) && prefix >= 12) {
			return (1==1);
		}

		inet_pton(AF_INET, "192.168.0.0", &safe_addr.sin_addr.s_addr);
		if (check_addr_range((struct sockaddr*)&safe_addr, 16, addr) && prefix >= 16) {
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

network_list_t get_overlapping_networks(struct sockaddr* addr_base, uint8_t prefix, network_list_t list)
{
	network_list_t result = NULL;
	network_list_t network_iterator = list;
	uint8_t min_public_prefix;

	if (addr_base->sa_family == AF_INET) {
		min_public_prefix = MINIMUM_IPV4_PUBLIC_PREFIX;
	} else if (addr_base->sa_family == AF_INET6) {
		min_public_prefix = MINIMUM_IPV6_PUBLIC_PREFIX;
	} else {
		print_error("Unexpected address family when checking for overlapping networks");
		return NULL;
	}

	while (network_iterator != NULL) {
		if (addr_base->sa_family == network_iterator->addr_base->sa_family) {
			if (prefix >= network_iterator->prefix) {
				if (check_addr_range(addr_base, prefix, network_iterator->addr_base) > 0
						&& (check_autoscannable_range(network_iterator->addr_base, network_iterator->prefix) > 0
							|| network_iterator->prefix < min_public_prefix)) {
					add_network(&result, network_iterator->addr_base, network_iterator->prefix);
				}
			} else {
				if (check_addr_range(network_iterator->addr_base, network_iterator->prefix, addr_base) > 0
						&& (check_autoscannable_range(addr_base, prefix) > 0
							|| prefix < min_public_prefix)) {
					add_network(&result, addr_base, prefix);
				}
			}
		}

		network_iterator = network_iterator->next;
	}

	return result;
}

