#ifndef _WIOMW_NEIGHBOURS_H_
#define _WIOMW_NEIGHBOURS_H_

/*
#define MAC_ADDR_LENGTH 18
#undef IP_ADDR_LENGTH
#undef NETBIOS_NAME_LENGTH
#undef VENDOR_NAME_LENGTH

typedef struct __neighbour_struct {
	char str_mac_addr[MAC_ADDR_LENGTH];
	char str_ip_addr[IP_ADDR_LENGTH];
	char str_netbios_name[NETBIOS_NAME_LENGTH];
	char str_vendor_name[VENDOR_NAME_LENGTH];
	time_t time_last_sent;
	time_t time_last_updated;
	int int_status;
} neighbour_t;

typedef struct __neighbourhood_struct {
	neighbour_t neighbour;
	struct __neighbourhood_struct* next;
} * neighbourhood_t;
*/
void print_neighbours();

#endif
