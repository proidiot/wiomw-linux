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

network_list_t combine_network_lists(network_list_t* list1, network_list_t list2);

network_list_t address_range_network_list(struct sockaddr* first_addr, struct sockaddr* last_addr);


long increment_addr(struct sockaddr* addr_base, uint8_t prefix, struct sockaddr* addr_to_increment);

int check_addr_range(struct sockaddr* addr_base, uint8_t prefix, struct sockaddr* addr_to_check);

int check_autoscannable_range(struct sockaddr* addr, uint8_t prefix);


network_list_t get_overlapping_networks(struct sockaddr* addr_base, uint8_t prefix, network_list_t list);

#endif
