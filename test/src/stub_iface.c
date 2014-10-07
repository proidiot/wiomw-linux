#include <config.h>

#include <sysexits.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <linux/if.h>

#ifndef DEJAGNU_H
#include <dejagnu.h>
#ifndef DEJAGNU_H
#define DEJAGNU_H
#endif
#endif

#include "../../src/iface.h"

void get_iface_name(char* name, const int ifindex)
{
	note("called stub function get_iface_name");
	snprintf(name, IFNAMSIZ, "eth%d", ifindex);
}

void get_iface_blacklisted(bool* blacklisted, const int ifindex)
{
	note("called stub function get_iface_blacklisted");
	*blacklisted = false;
}

void get_iface_mac(unsigned char* mac, const int ifindex)
{
	note("called stub function get_iface_mac");
	mac[0] = 0x01;
	mac[1] = 0x23;
	mac[2] = 0x45;
	mac[3] = 0x67;
	mac[4] = 0x89;
	mac[5] = 0xAB;
}

void print_iface_by_index(FILE* stream, const int ifindex)
{
	note("called stub function print_iface_by_index");
	fprintf(stream, "{\"iface_status\":\"fake\",\"test_data\":1,\"index\":\"eth%d\"}", ifindex);
}

void clean_iface_table()
{
	note("called stub function clean_iface_table");
}

