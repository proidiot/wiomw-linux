#ifndef _WIOMW_IFADDR_H_
#define _WIOMW_IFADDR_H_

#include <linux/netlink.h>
#include <stdio.h>

int rtm_newaddr_cb(const struct nlmsghdr* nl_header, void* closure);
int rtm_deladdr_cb(const struct nlmsghdr* nl_header, void* closure);
int rtm_getaddr_cb(const struct nlmsghdr* nl_header, void* closure);

void print_ifaddrs(FILE* stream);
void clean_ifaddr_table();

#endif

