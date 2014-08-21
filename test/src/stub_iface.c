#include <config.h>

#include <sysexits.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <dejagnu.h>

#include "../../src/iface.h"

void get_iface_name(char* name, const int ifindex)
{
	xfail("called stub function get_iface_name");
	exit(EX_UNAVAILABLE);
}

void get_iface_blacklisted(bool* blacklisted, const int ifindex)
{
	xfail("called stub function get_iface_blacklisted");
	exit(EX_UNAVAILABLE);
}

void get_iface_mac(unsigned char* mac, const int ifindex)
{
	xfail("called stub function get_iface_mac");
	exit(EX_UNAVAILABLE);
}

void print_iface_by_index(FILE* stream, const int ifindex)
{
	xfail("called stub function print_iface_by_index");
	exit(EX_UNAVAILABLE);
}

void clean_iface_table()
{
	xfail("called stub function clean_iface_table");
	exit(EX_UNAVAILABLE);
}

