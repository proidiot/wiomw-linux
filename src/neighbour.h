#ifndef _WIOMW_NEIGHBOUR_H_
#define _WIOMW_NEIGHBOUR_H_

typedef struct _neighbour_struct* neighbour_t;

void add_ifaddr_entry(int index, unsigned char family, struct sockaddr* ip, unsigned char* mac);

int rtm_newneigh_cb(const struct nlmsghdr* nl_header, void* closure);
int rtm_delneigh_cb(const struct nlmsghdr* nl_header, void* closure);

#endif
