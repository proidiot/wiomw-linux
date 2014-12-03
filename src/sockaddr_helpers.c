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
#include "sockaddr_helpers.h"
#include "syslog_syserror.h"
#include <syslog.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <sysexits.h>
#include <limits.h>
#include <stdbool.h>


void add_network(network_list_t* list, struct sockaddr* addr_base, uint8_t prefix)
{
	network_list_t temp;
	if (addr_base == NULL) {
		return;
	}

	temp = (network_list_t)malloc(sizeof(struct _network_list_struct));
	if (temp == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to allocate memory");
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

network_list_t combine_network_lists(network_list_t* list1, network_list_t list2)
{
	if (list1 == NULL) {
		return list2;
	} else if (list2 == NULL) {
		return *list1;
	} else if (*list1 == NULL) {
		*list1 = list2;
		return *list1;
	} else {
		network_list_t templist = *list1;
		while (templist->next != NULL) {
			templist = templist->next;
		}
		templist->next = list2;
		return *list1;
	}
}

network_list_t address_range_network_list(struct sockaddr* first, struct sockaddr* last)
{
	network_list_t result = NULL;
	if (first == NULL && last == NULL) {
		return result;
	} else if (first == NULL && last->sa_family == AF_INET) {
		struct sockaddr* temp = (struct sockaddr*)malloc(sizeof(struct sockaddr_in));
		memcpy(temp, last, sizeof(struct sockaddr_in));
		add_network(&result, last, 32);
	} else if (first == NULL && last->sa_family == AF_INET6) {
		struct sockaddr* temp = (struct sockaddr*)malloc(sizeof(struct sockaddr_in6));
		memcpy(temp, last, sizeof(struct sockaddr_in6));
		add_network(&result, last, 128);
	} else if (last == NULL && first->sa_family == AF_INET) {
		struct sockaddr* temp = (struct sockaddr*)malloc(sizeof(struct sockaddr_in));
		memcpy(temp, first, sizeof(struct sockaddr_in));
		add_network(&result, first, 32);
	} else if (last == NULL && first->sa_family == AF_INET6) {
		struct sockaddr* temp = (struct sockaddr*)malloc(sizeof(struct sockaddr_in6));
		memcpy(temp, first, sizeof(struct sockaddr_in6));
		add_network(&result, first, 128);
	} else if (last == NULL || first == NULL) {
		syslog(LOG_ERR, "Unknown address family in range");
	} else if (first->sa_family != last->sa_family) {
		syslog(LOG_ERR, "Cannot create an address range between addresses of different types");
	} else if (first->sa_family == AF_INET) {
		unsigned long first_ip = ntohl(((struct sockaddr_in*)first)->sin_addr.s_addr);
		unsigned long last_ip = ntohl(((struct sockaddr_in*)last)->sin_addr.s_addr);
		unsigned long current;
		if (first_ip > last_ip) {
			unsigned long swap = first_ip;
			first_ip = last_ip;
			last_ip = swap;
		}

		for (current = first_ip; current <= last_ip; current++) {
			uint8_t prefix = 32;
			struct sockaddr_in* temp = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
			memset(temp, 0, sizeof(struct sockaddr_in));
			temp->sin_family = AF_INET;
			while (prefix > 0 && (current + (0xFFFFFFFF >> prefix)) <= last_ip) {
				prefix--;
			}
			if (prefix < 32) {
				prefix++;
			}
			current += (0xFFFFFFFF >> prefix);
			temp->sin_addr.s_addr = htonl(current);
			add_network(&result, (struct sockaddr*)temp, prefix);
		}
	} else if (first->sa_family == AF_INET6) {
		struct sockaddr_in6* first_ip = (struct sockaddr_in6*)first;
		struct sockaddr_in6* last_ip = (struct sockaddr_in6*)last;
		struct sockaddr_in6* current = (struct sockaddr_in6*)malloc(sizeof(struct sockaddr_in6));
		int change_offset = 0;
		int partial_prefix = 8;
		while (change_offset < 16 && first_ip->sin6_addr.s6_addr[change_offset] == last_ip->sin6_addr.s6_addr[change_offset]) {
			change_offset++;
		}
		if (change_offset < 16 && first_ip->sin6_addr.s6_addr[change_offset] > last_ip->sin6_addr.s6_addr[change_offset]) {
			first_ip = (struct sockaddr_in6*)last;
			last_ip = (struct sockaddr_in6*)first;
		}
		memcpy(current, first_ip, sizeof(struct sockaddr_in6));
		while (partial_prefix > 0
				&& (current->sin6_addr.s6_addr[change_offset] + (0xFF >> partial_prefix))
					<= last_ip->sin6_addr.s6_addr[change_offset]) {
			partial_prefix--;
		}
		if (partial_prefix < 8) {
			partial_prefix++;
		}
		current->sin6_addr.s6_addr[change_offset] += (0xFF >> partial_prefix);
		add_network(&result, (struct sockaddr*)current, (8 * change_offset) + partial_prefix);
	} else {
		syslog(LOG_ERR, "Unknown address family in range");
	}
	return result;
}


long increment_addr(struct sockaddr* addr_base, uint8_t prefix, struct sockaddr* addr_to_increment)
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
		syslog(LOG_ERR, "Full range IP enumeration is not allowed");
		return -999;
	} else if (prefix == 0 && addr_base->sa_family == AF_INET6) {
		syslog(LOG_ERR, "Full range IP enumeration is not allowed");
		return -999;
	} else if (addr_base->sa_family == AF_INET) {
		struct sockaddr_in* base = (struct sockaddr_in*)addr_base;
		struct sockaddr_in* addr = (struct sockaddr_in*)addr_to_increment;
		uint8_t suffix = 32 - prefix;
		unsigned long base_ip = (ntohl(base->sin_addr.s_addr) >> suffix) << suffix;
		unsigned long bcast_ip = (((ntohl(base->sin_addr.s_addr) >> suffix) + 1) << suffix) - 1;
		unsigned long ip = ntohl(addr->sin_addr.s_addr);
		addr_to_increment->sa_family = AF_INET;

		if (ip == 0) {
			ip = base_ip + 1;
			addr_to_increment->sa_family = AF_INET;
		} else if (ip >= base_ip && ip < bcast_ip) {
			ip++;
		} else {
			return -10;
		}

		addr->sin_family = AF_INET;
		addr->sin_addr.s_addr = htonl(ip);

		return ((bcast_ip - ip) >= LONG_MAX)? LONG_MAX : (bcast_ip - ip);
	} else if (addr_base->sa_family == AF_INET6) {
		struct sockaddr_in6* base = (struct sockaddr_in6*)addr_base;
		struct sockaddr_in6* addr = (struct sockaddr_in6*)addr_to_increment;
		int i = 0;
		int last_non_full = 16; /* becomes -1, the real default, once we verify that this isn't the first address */
		bool first_addr = true;
		unsigned long remaining = 0;
		uint8_t tprefix = tprefix;
		addr_to_increment->sa_family = AF_INET6;
		for (i = 0; first_addr && i < 16; i++) {
			if (addr->sin6_addr.s6_addr[i] != 0x00) {
				first_addr = false;
				last_non_full = -1;
			}
		}
		for (i = 0; i < 16; i++) {
			if (tprefix >= 8) {
				if (first_addr) {
					addr->sin6_addr.s6_addr[i] = base->sin6_addr.s6_addr[i];
				} else if (addr->sin6_addr.s6_addr[i] != base->sin6_addr.s6_addr[i]) {
					return -10;
					/* network prefix doesn't match and it wasn't a fresh address, so out of range */
				}
				tprefix -= 8;
			} else if (tprefix > 0) {
				unsigned char low = base->sin6_addr.s6_addr[i] & (0xFF << (8 - tprefix));
				unsigned char high = base->sin6_addr.s6_addr[i] | (0xFF >> tprefix);
				unsigned char current = addr->sin6_addr.s6_addr[i];
				if (first_addr) {
					addr->sin6_addr.s6_addr[i] = low;
					remaining = high - low;
				} else if (current < low || current > high) {
					return -10;
					/* network prefix doesn't match and it wasn't a fresh address */
				} else if (current != high) {
					last_non_full = i;
					remaining = high - current;
				}
				tprefix = 0;
			} else {
				if (remaining != ULONG_MAX) {
					if (remaining >= (ULONG_MAX / 256)) {
						remaining = ULONG_MAX;
					} else {
						remaining *= 256;
					}
				}
				if (first_addr) {
					addr->sin6_addr.s6_addr[i] = 0x00;
					if (remaining != ULONG_MAX) {
						remaining += 256;
					}
				} else if (addr->sin6_addr.s6_addr[i] != 0xFF) {
					last_non_full = i;
					if (remaining != ULONG_MAX) {
						remaining += (0xFF - addr->sin6_addr.s6_addr[i]);
					}
				}
			}
		}

		if (last_non_full >= 0) {
			addr->sin6_addr.s6_addr[last_non_full] += 1;
			for (i = last_non_full; i < 16; i++) {
				addr->sin6_addr.s6_addr[i] = 0x00;
			}
			remaining -= 1;
		} else {
			return -10;
			/* this could only have happened if the address given was the broadcast */
		}

		return (remaining >= LONG_MAX)? LONG_MAX : remaining;
	} else {
		syslog(LOG_ERR, "Unknown address family for base address");
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
		struct sockaddr_in6* base = (struct sockaddr_in6*)addr_base;
		struct sockaddr_in6* addr = (struct sockaddr_in6*)addr_to_check;
		int i = 0;
		for (i = 0; i < 16; i++) {
			if (base->sin6_addr.s6_addr[i] != addr->sin6_addr.s6_addr[i]) {
				return (1==0);
			}
		}
		return (1==1);
	} else if (prefix == 0) {
		return (1==1);
	} else if (addr_base->sa_family == AF_INET) {
		struct sockaddr_in* base = (struct sockaddr_in*)addr_base;
		struct sockaddr_in* addr = (struct sockaddr_in*)addr_to_check;
		uint8_t suffix = 32 - prefix;
		unsigned long base_ip = (ntohl(base->sin_addr.s_addr) >> suffix) << suffix;
		unsigned long bcast_ip = (((ntohl(base->sin_addr.s_addr) >> suffix) + 1) << suffix) - 1;
		unsigned long ip = ntohl(addr->sin_addr.s_addr);

		if (ip >= base_ip && ip <= bcast_ip) {
			return (1==1);
		} else {
			return (1==0);
		}
	} else if (addr_base->sa_family == AF_INET6) {
		struct sockaddr_in6* base = (struct sockaddr_in6*)addr_base;
		struct sockaddr_in6* addr = (struct sockaddr_in6*)addr_to_check;
		int i = 0;
		uint8_t tprefix = prefix;
		for (i = 0; i < 16; i++) {
			if (tprefix >= 8) {
				if (base->sin6_addr.s6_addr[i] != addr->sin6_addr.s6_addr[i]) {
					return (1==0);
				}
				tprefix -= 8;
			} else if (tprefix > 0) {
				unsigned char low = base->sin6_addr.s6_addr[i] & (0xFF << (8 - tprefix));
				unsigned char high = base->sin6_addr.s6_addr[i] | (0xFF >> tprefix);
				unsigned char check = addr->sin6_addr.s6_addr[i];
				return (low <= check) && (check <= high);
			} else {
				return (1==1);
			}
		}
		syslog(LOG_ERR, "Internal error while checking IP range");
		return -999;
	} else {
		syslog(LOG_ERR, "Unknown address family for base address");
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

		/* TODO: test ranges, etc. */

		return (1==0);
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 safe_addr;
		socklen_t safe_len = sizeof(struct sockaddr_in6);
		memset(&safe_addr, 0, safe_len);
		safe_addr.sin6_family = AF_INET6;

		inet_pton(AF_INET6, "fc00::", &safe_addr.sin6_addr.s6_addr);
		if (check_addr_range((struct sockaddr*)&safe_addr, 7, addr) && prefix >= 7) {
			return (1==1);
		}

		/* fec0::/7 was a previous candidate for a private range, questionable if it should be included */
		/*
		inet_pton(AF_INET6, "fec0::", &safe_addr.sin6_addr.s6_addr);
		if (check_addr_range((struct sockaddr*)&safe_addr, 10, addr) && prefix >= 10) {
			return (1==1);
		}
		*/

		/* TODO: private IPv4 ranges in mapped addresses, test ranges, etc. */

		return (1==0);
	} else {
		syslog(LOG_ERR, "Unable to check if address is within an acceptable range: Unknown address family");
		return -1;
	}
}

network_list_t get_overlapping_networks(struct sockaddr* addr_base, uint8_t prefix, network_list_t list)
{
	/* TODO: differentiate between specififed network and real network so
	 * that identity/broadcast address inclusion rules can be resolved,
	 * also maybe add a config option to override default rules? */
	network_list_t result = NULL;
	network_list_t network_iterator = list;
	uint8_t min_public_prefix;

	if (addr_base->sa_family == AF_INET) {
		min_public_prefix = CONFIG_OPTION_IPV4_PUBLIC_PREFIX;
	} else if (addr_base->sa_family == AF_INET6) {
		min_public_prefix = CONFIG_OPTION_IPV6_PUBLIC_PREFIX;
	} else {
		syslog(LOG_ERR, "Unexpected address family when checking for overlapping networks");
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

