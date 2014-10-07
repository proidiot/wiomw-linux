#include <config.h>

#include <dejagnu.h>
#ifndef DEJAGNU_H
#define DEJAGNU_H
#endif

#include <stdlib.h>
#include <time.h>
#include <libmnl/libmnl.h>

#include "bindiff.h"
#include "stub_iface.c"
#include "stub_neighbour.c"

#include "../../src/data_tracker.c"
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
	const uint32_t ip4 = htonl(0xC0A80001);
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
	if (!mnl_attr_put_u32_check(nlh, MNL_SOCKET_BUFFER_SIZE, IFA_ADDRESS, ip4)) {
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

void test_ifaddr_prepare_data_tracker()
{
	note("running test_ifaddr_prepare_data_tracker");

	struct ifaddr_history_data* actual_hdata;
	struct ifaddr_nohistory_data* actual_nhdata;
	struct ifaddr_history_data expected_hdata;
	struct data_tracker* tracker;

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
	const uint32_t ip4 = htonl(0xC0A80001);
	const uint32_t lip4 = htonl(0x7F000001);
	const uint32_t bip4 = htonl(0xC0A800FF);
	const uint32_t aip4 = htonl(0xC0A80000);
	srandom(time(NULL));
	for (i = 0; i < MNL_SOCKET_BUFFER_SIZE; i++) {
		buf[i] = (unsigned char)(((unsigned long int)random()) % 8);
	}
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = 0;
	ifa = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifaddrmsg));
	ifa->ifa_family = family;
	ifa->ifa_prefixlen = prefixlen;
	ifa->ifa_flags = ifa_flags;
	ifa->ifa_scope = scope;
	ifa->ifa_index = ifindex;
	if (!mnl_attr_put_u32_check(nlh, MNL_SOCKET_BUFFER_SIZE, IFA_BROADCAST, bip4)) {
		fail("unable to put ifa_broadcast");
	}
	if (!mnl_attr_put_u32_check(nlh, MNL_SOCKET_BUFFER_SIZE, IFA_ADDRESS, ip4)) {
		fail("unable to put ifa_address");
	}
	if (!mnl_attr_put_strz_check(nlh, MNL_SOCKET_BUFFER_SIZE, IFA_LABEL, label)) {
		fail("unable to put ifa_label");
	}
	if (!mnl_attr_put_u32_check(nlh, MNL_SOCKET_BUFFER_SIZE, IFA_LOCAL, lip4)) {
		fail("unable to put ifa_local");
	}
	if (!mnl_attr_put_u32_check(nlh, MNL_SOCKET_BUFFER_SIZE, IFA_ANYCAST, aip4)) {
		fail("unable to put ifa_anycast");
	}

	memset(&expected_hdata, 0x00, sizeof(struct ifaddr_history_data));

	expected_hdata.local.ip4.s_addr = lip4;
	expected_hdata.bcast.ip4.s_addr = bip4;
	expected_hdata.acast.ip4.s_addr = aip4;
	expected_hdata.ifa_prefixlen = prefixlen;
	expected_hdata.ifa_flags = ifa_flags;
	expected_hdata.ifa_scope = scope;
	strcpy(expected_hdata.label, label);

	if ((tracker = prepare_data_tracker(ifaddr_data_size, nlh, &ifaddr_header_cb, &ifaddr_attr_cb)) == NULL) {
		fail("prepare_data_tracker returned NULL");
	} else {
		struct tracked_data tdata = get_tracked_data(tracker);
		actual_nhdata = (struct ifaddr_nohistory_data*)(tdata.nohistory_data);
		actual_hdata = (struct ifaddr_history_data*)(tdata.history_data);
		if (actual_nhdata == NULL || actual_hdata == NULL) {
			fail("received NULL actual data");
		} else {
			pass("actual data returned non-NULL");
		}
	}

	if (actual_nhdata->ifa_index != ifindex || actual_nhdata->addr.ip4.s_addr != ip4 || actual_nhdata->ifa_family != family) {
		fail("nohistory_data did not match");
	} else {
		pass("nohistory_data appeared to be fine");
	}

	if (memcmp(actual_hdata, &expected_hdata, sizeof(struct ifaddr_history_data)) != 0) {
		char* diff = bindiff((unsigned char*)&expected_hdata, (unsigned char*)actual_hdata, sizeof(struct ifaddr_history_data), 0);
		fail("history_data did not match");
		note("\n%s", diff);
		free(diff);
	} else {
		pass("history_data matches");
	}
}

int main()
{
	set_configuration(0, NULL);

	test_ifaddr_header_cb();

	test_ifaddr_prepare_data_tracker();

	return 0;
}

