#ifndef _WIOMW_IFACE_H_
#define _WIOMW_IFACE_H_

typedef struct _iface_struct* iface_t;
typedef struct _ifaddr_struct* ifaddr_t;

iface_t get_iface_by_index(int index);

int rtm_newlink_cb(const struct nlmsghdr* nl_header, void* closure);
int rtm_dellink_cb(const struct nlmsghdr* nl_header, void* closure);
int rtm_newaddr_cb(const struct nlmsghdr* nl_header, void* closure);
int rtm_deladdr_cb(const struct nlmsghdr* nl_header, void* closure);

#endif
