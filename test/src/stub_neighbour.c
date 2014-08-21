#include <config.h>

#include <sysexits.h>
#include <stdlib.h>
#include <dejagnu.h>
#include "../../src/ip.h"

#include "../../src/neighbour.h"

int add_ifaddr_entry(const int index, const unsigned char family, const union ip addr, const unsigned char* mac)
{
	xfail("called stub function add_ifaddr_entry");
	exit(EX_UNAVAILABLE);
}

int remove_ifaddr_entry(const int index, const unsigned char family, const union ip addr, const unsigned char* mac)
{
	xfail("called stub function remove_ifaddr_entry");
	exit(EX_UNAVAILABLE);
}

