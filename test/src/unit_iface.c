#include <config.h>
#include <dejagnu.h>

#include <stdlib.h>
#include <time.h>
#include <libmnl/libmnl.h>
#include <linux/if_arp.h>

#include "bindiff.h"

#include "../../src/data_tracker.c"
#include "../../src/iface.c"

void test_iface_header_cb()
{
	note("running test_iface_header_cb");

	struct iface_history_data actual_hdata;
	struct iface_nohistory_data actual_nhdata;
	const struct tracked_data tdata = {
		.history_data = &actual_hdata,
		.nohistory_data = &actual_nhdata
	};
	struct iface_history_data expected_hdata;

	struct nlmsghdr* nlh = NULL;
	struct ifinfomsg* ifi = NULL;
	unsigned char buf[MNL_SOCKET_BUFFER_SIZE];
	unsigned int i = 0;
	const unsigned char family = AF_UNSPEC;
	const int ifindex = 1;
	const unsigned short hwtype = ARPHRD_ETHER;
	const unsigned int ifi_flags = IFF_UP | IFF_RUNNING | IFF_DYNAMIC;
	const unsigned int ifi_change = 0xFFFFFFFF;
	const char* qdsp = "pfifo_fast";
	const char* name = "eth0";
	const uint32_t mtu = 1500;
	const unsigned char mac[6] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB};
	srandom(time(NULL));
	for (i = 0; i < MNL_SOCKET_BUFFER_SIZE; i++) {
		buf[i] = (unsigned char)(((unsigned long int)random()) % 8);
	}
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = 0;
	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_family = family;
	ifi->ifi_index = ifindex;
	ifi->ifi_type = hwtype;
	ifi->ifi_flags = ifi_flags;
	ifi->ifi_change = ifi_change;
	if (!mnl_attr_put_check(nlh, MNL_SOCKET_BUFFER_SIZE, IFLA_ADDRESS, 6, mac)) {
		fail("unable to put ifla_address");
	}

	memset(&actual_hdata, 0x00, sizeof(struct iface_history_data));

	memcpy(&expected_hdata, &actual_hdata, sizeof(struct iface_history_data));
	expected_hdata.ifi_family = family;
	expected_hdata.ifi_type = hwtype;
	expected_hdata.ifi_flags = ifi_flags;
	/*
	for (i = 0; i < 6; i++) {
		expected_hdata.mac[i] = mac[i];
	}
	expected_hdata.mtu = mtu;
	expected_hdata.link = ifindex;
	strcpy(expected_hdata.qdsp, qdsp);
	strcpy(expected_hdata.name, name);
	*/

	if (get_iface_header_cb(nlh, tdata) != sizeof(struct ifinfomsg)) {
		fail("get_iface_header_cb returned the wrong size");
	} else {
		pass("get_iface_header_cb returned the expected size");
	}

	if (actual_nhdata.ifi_index != ifindex) {
		fail("nohistory_data did not match");
	} else {
		pass("nohistory_data appeared to be fine");
	}

	if (memcmp(&actual_hdata, &expected_hdata, sizeof(struct iface_history_data)) != 0) {
		char* diff = bindiff((unsigned char*)&expected_hdata, (unsigned char*)&actual_hdata, sizeof(struct iface_history_data), 0);
		fail("history_data did not match");
		note("\n%s", diff);
		free(diff);
	} else {
		pass("history_data matches");
	}
}

void test_iface_prepare_data_tracker()
{
	note("running test_iface_prepare_data_tracker");

	struct iface_history_data* actual_hdata;
	struct iface_nohistory_data* actual_nhdata;
	struct iface_history_data expected_hdata;
	struct data_tracker* tracker;

	struct nlmsghdr* nlh = NULL;
	struct ifinfomsg* ifi = NULL;
	unsigned char buf[MNL_SOCKET_BUFFER_SIZE];
	unsigned int i = 0;
	const unsigned char family = AF_UNSPEC;
	const int ifindex = 1;
	const unsigned short hwtype = ARPHRD_ETHER;
	const unsigned int ifi_flags = IFF_UP | IFF_RUNNING | IFF_DYNAMIC;
	const unsigned int ifi_change = 0xFFFFFFFF;
	const char* qdsp = "pfifo_fast";
	const char* name = "eth0";
	const uint32_t mtu = 1500;
	const int link = ifindex;
	const unsigned char mac[6] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB};
	const unsigned char bmac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	srandom(time(NULL));
	for (i = 0; i < MNL_SOCKET_BUFFER_SIZE; i++) {
		buf[i] = (unsigned char)(((unsigned long int)random()) % 8);
	}
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = 0;
	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_family = family;
	ifi->ifi_index = ifindex;
	ifi->ifi_type = hwtype;
	ifi->ifi_flags = ifi_flags;
	ifi->ifi_change = ifi_change;
	if (!mnl_attr_put_check(nlh, MNL_SOCKET_BUFFER_SIZE, IFLA_BROADCAST, 6, bmac)) {
		fail("unable to put ifla_broadcast");
	}
	if (!mnl_attr_put_check(nlh, MNL_SOCKET_BUFFER_SIZE, IFLA_ADDRESS, 6, mac)) {
		fail("unable to put ifla_address");
	}
	if (!mnl_attr_put_strz_check(nlh, MNL_SOCKET_BUFFER_SIZE, IFLA_IFNAME, name)) {
		fail("unable to put ifla_ifname");
	}
	if (!mnl_attr_put_u32_check(nlh, MNL_SOCKET_BUFFER_SIZE, IFLA_MTU, mtu)) {
		fail("unable to put ifla_mtu");
	}
	if (!mnl_attr_put_check(nlh, MNL_SOCKET_BUFFER_SIZE, IFLA_LINK, sizeof(int), &link)) {
		fail("unable to put ifla_link");
	}
	if (!mnl_attr_put_strz_check(nlh, MNL_SOCKET_BUFFER_SIZE, IFLA_QDISC, qdsp)) {
		fail("unable to put ifla_qdisc");
	}

	memset(&expected_hdata, 0x00, sizeof(struct iface_history_data));

	expected_hdata.ifi_family = family;
	expected_hdata.ifi_type = hwtype;
	expected_hdata.ifi_flags = ifi_flags;
	for (i = 0; i < 6; i++) {
		expected_hdata.mac[i] = mac[i];
	}
	for (i = 0; i < 6; i++) {
		expected_hdata.bmac[i] = bmac[i];
	}
	expected_hdata.mtu = mtu;
	expected_hdata.link = link;
	strcpy(expected_hdata.qdsp, qdsp);
	strcpy(expected_hdata.name, name);

	if ((tracker = prepare_data_tracker(iface_data_size, nlh, &get_iface_header_cb, &get_iface_attr_cb)) == NULL) {
		fail("prepare_data_tracker returned NULL");
	} else {
		struct tracked_data tdata = get_tracked_data(tracker);
		actual_nhdata = (struct iface_nohistory_data*)(tdata.nohistory_data);
		actual_hdata = (struct iface_history_data*)(tdata.history_data);
		if (actual_nhdata == NULL || actual_hdata == NULL) {
			fail("received NULL actual data");
		} else {
			pass("actual data returned non-NULL");
		}
	}

	if (actual_nhdata->ifi_index != ifindex) {
		fail("nohistory_data did not match");
	} else {
		pass("nohistory_data appeared to be fine");
	}

	if (memcmp(actual_hdata, &expected_hdata, sizeof(struct iface_history_data)) != 0) {
		char* diff = bindiff((unsigned char*)&expected_hdata, (unsigned char*)actual_hdata, sizeof(struct iface_history_data), 0);
		fail("history_data did not match");
		note("\n%s", diff);
		free(diff);
	} else {
		pass("history_data matches");
	}

	abort_data_tracker(tracker);
}

void test_print_iface()
{
	note("running test_print_iface");

	const struct iface_history_data hdata =
	{
		.ifi_family = AF_UNSPEC,
		.ifi_type = ARPHRD_ETHER,
		.ifi_flags = IFF_UP | IFF_RUNNING | IFF_DYNAMIC,
		.mac = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB},
		.bmac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		.mtu = 1500,
		.link = 1,
		.blacklisted = false,
		.qdsp = "pfifo_fast",
		.name = "eth0"
	};
	const struct iface_nohistory_data nhdata =
	{
		.ifi_index = 1
	};
	const struct tracked_data data =
	{
		.nohistory_data = (void*)&nhdata,
		.history_data = (void*)&hdata
	};
	FILE* stream = tmpfile();

	const char* expected = "\"family\":\"AF_UNSPEC\",\"type\":"
		"\"ARPHRD_ETHER\",\"up\":1,\"running\":1,\"dynamic\":1,"
		"\"volatile\":1,\"mac\":\"01:23:45:67:89:AB\",\"bcast_mac\":"
		"\"FF:FF:FF:FF:FF:FF\",\"mtu\":1500,\"real_iface\":\"eth0\","
		"\"qdsp\":\"pfifo_fast\",\"name\":\"eth0\",\"blacklisted\":0,"
		"\"rx_packets\":0,\"tx_packets\":0,\"rx_bytes\":0,"
		"\"tx_bytes\":0,\"rx_errors\":0,\"tx_errors\":0,"
		"\"rx_dropped\":0,\"tx_dropped\":0,\"multicast\":0,"
		"\"collisions\":0,\"rx_length_errors\":0,\"rx_over_errors\":0,"
		"\"rx_crc_errors\":0,\"rx_frame_errors\":0,"
		"\"rx_fifo_errors\":0,\"rx_missed_errors\":0,"
		"\"tx_aborted_errors\":0,\"tx_carrier_errors\":0,"
		"\"tx_fifo_errors\":0,\"tx_heartbeat_errors\":0,"
		"\"tx_window_errors\":0,\"rx_compressed\":0,"
		"\"tx_compressed\":0,";
	char actual[BUFSIZ];

	print_iface(stream, data);

	rewind(stream);

	if (fgets(actual, BUFSIZ, stream) == NULL) {
		fail("unable to fgets");
	}

	fclose(stream);

	if (strncmp(expected, actual, BUFSIZ) != 0) {
		fail("print_iface did not match");
		note("expected: %s", expected);
		note("actual: %s", actual);
	} else {
		pass("print_iface matched");
	}
}

int main()
{
	set_configuration(0, NULL);

	test_iface_header_cb();

	test_iface_prepare_data_tracker();

	test_print_iface();

	return 0;
}

