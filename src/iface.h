#ifndef _WIOMW_IFACE_H_
#define _WIOMW_IFACE_H_

#include <linux/netlink.h>
#include <stdio.h>
#include <stdbool.h>

void get_iface_name(char* name, const int ifindex);
void get_iface_blacklisted(bool* blacklisted, const int ifindex);
void get_iface_mac(unsigned char* mac, const int ifindex);

void print_iface_by_index(FILE* stream, const int ifindex);

int rtm_newlink_cb(const struct nlmsghdr* nl_header, void* closure);
int rtm_dellink_cb(const struct nlmsghdr* nl_header, void* closure);
int rtm_getlink_cb(const struct nlmsghdr* nl_header, void* closure);

void clean_iface_table();

#endif
