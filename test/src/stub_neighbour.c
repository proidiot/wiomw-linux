#include <config.h>

#ifndef DEJAGNU_H
#include <dejagnu.h>
#ifndef DEJAGNU_H
#define DEJAGNU_H
#endif
#endif

#include <sysexits.h>
#include <stdlib.h>
#include <libmnl/libmnl.h>
#include "../../src/ip.h"

#include "../../src/neighbour.h"

int add_ifaddr_entry(const int index, const unsigned char family, const union ip addr, const unsigned char* mac)
{
	note("called stub function add_ifaddr_entry");
	return MNL_CB_OK;
}

int remove_ifaddr_entry(const int index, const unsigned char family, const union ip addr, const unsigned char* mac)
{
	note("called stub function remove_ifaddr_entry");
	return MNL_CB_OK;
}

