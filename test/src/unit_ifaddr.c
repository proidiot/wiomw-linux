#include <config.h>
#include <dejagnu.h>

#include <stdlib.h>
#include <time.h>
#include <libmnl/libmnl.h>

#include "bindiff.h"

#include "../../src/ifaddr.c"

void test_ifaddr_header_cb()
{
	note("running test_ifaddr_header_cb");

	struct ifaddr_history_data actual_hdata;
	struct ifaddr_nohistory_data actual_nhdata;
	const struct tracked_data tdata = {
		.history_data = &actual_hdata,
		.nohistory_data = &actual_nhdata
	};
	struct ifaddr_history_data expected_hdata;

	struct nlmsghdr* nlh = NULL;
	struct ifaddrmsg* ifa = NULL;
	unsigned char buf[MNL_SOCKET_BUFFER_SIZE];
	unsigned int i = 0;
	const unsigned char family = AF_INET;
	const int ifindex = 1;
	const unsigned char prefixlen = 24;
	const unsigned char scope = 0x02;
	const unsigned char ifa_flags = 0;
	const char* label = "eth0:1";
	unsigned char ip4[4];
	ip4[0] = 0xC0;
	ip4[1] = 0xA8;
	ip4[2] = 0x00;
	ip4[3] = 0x01;
	srandom(time(NULL));
	for (i = 0; i < MNL_SOCKET_BUFFER_SIZE; i++) {
		buf[i] = (unsigned char)(((unsigned long int)random()) % 8);
	}
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETADDR;
	nlh->nlmsg_flags = 0;
	ifa = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifaddrmsg));
	ifa->ifa_family = family;
	ifa->ifa_index = ifindex;
	ifa->ifa_scope = scope;
	ifa->ifa_flags = ifa_flags;
	ifa->ifa_prefixlen = prefixlen;
	if (!mnl_attr_put_check(nlh, MNL_SOCKET_BUFFER_SIZE, IFA_ADDRESS, 4, ip4)) {
		fail("unable to put address");
	}
	if (!mnl_attr_put_strz_check(nlh, MNL_SOCKET_BUFFER_SIZE, IFA_LABEL, label)) {
		fail("unable to put label");
	}

	memset(&actual_hdata, 0x00, sizeof(struct ifaddr_history_data));

	memcpy(&expected_hdata, &actual_hdata, sizeof(struct ifaddr_history_data));
	expected_hdata.ifa_prefixlen = prefixlen;
	expected_hdata.ifa_scope = scope;
	expected_hdata.ifa_flags = ifa_flags;
	/*strcpy(expected_hdata.label, label); // NOT IN HEADER, NUB! */

	if (ifaddr_header_cb(nlh, tdata) != sizeof(struct ifaddrmsg)) {
		fail("ifaddr_header_cb returned the wrong size");
	} else {
		pass("ifaddr_header_cb returned the expected size");
	}

	if (actual_nhdata.ifa_index != ifindex || actual_nhdata.ifa_family != family) {
		fail("nohistory_data did not match");
	} else {
		pass("nohistory_data appeared to be fine");
	}

	if (memcmp(&actual_hdata, &expected_hdata, sizeof(struct ifaddr_history_data)) != 0) {
		char* diff = bindiff((unsigned char*)&expected_hdata, (unsigned char*)&actual_hdata, sizeof(struct ifaddr_history_data), 0);
		fail("history_data did not match");
		note("\n%s", diff);
		free(diff);
	} else {
		pass("history_data matches");
	}
}

int main()
{
	test_ifaddr_header_cb();

	return 0;
}

