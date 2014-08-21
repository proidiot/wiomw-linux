#ifndef _WIOMW_NEIGHBOUR_H_
#define _WIOMW_NEIGHBOUR_H_

#include <linux/netlink.h>
#include <stdio.h>
#include "ip.h"

int add_ifaddr_entry(const int index, const unsigned char family, const union ip addr, const unsigned char* mac);
int remove_ifaddr_entry(const int index, const unsigned char family, const union ip addr, const unsigned char* mac);

int rtm_newneigh_cb(const struct nlmsghdr* nl_header, void* closure);
int rtm_delneigh_cb(const struct nlmsghdr* nl_header, void* closure);
int rtm_getneigh_cb(const struct nlmsghdr* nl_header, void* closure);

void print_neighbours(FILE* stream);
void clean_neighbour_table();

#endif
