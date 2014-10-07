#include <config.h>
#include <dejagnu.h>

#include <stdlib.h>
#include <time.h>
#include <libmnl/libmnl.h>

#include "bindiff.h"
#include "stub_iface.c"

#include "../../src/configuration.h"
#include "../../src/neighbour.c"
#include "../../src/data_tracker.c"

void test_neighbour_header_cb()
{
	note("running test_neighbour_header_cb");

	struct neighbour_history_data actual_hdata;
	struct neighbour_nohistory_data actual_nhdata;
	const struct tracked_data tdata = {
		.history_data = &actual_hdata,
		.nohistory_data = &actual_nhdata
	};
	struct neighbour_history_data expected_hdata;

	struct nlmsghdr* nlh = NULL;
	struct ndmsg* ndm = NULL;
	unsigned char buf[MNL_SOCKET_BUFFER_SIZE];
	unsigned int i = 0;
	const uint8_t family = AF_INET;
	const int ifindex = 1;
	const uint8_t state = NUD_REACHABLE | NUD_STALE;
	const uint8_t ndm_flags = 0;
	const unsigned char mac[6] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB};
	const uint32_t ip4 = htonl(0xC0A80001);
	srandom(time(NULL));
	for (i = 0; i < MNL_SOCKET_BUFFER_SIZE; i++) {
		buf[i] = (unsigned char)(((unsigned long int)random()) % 8);
	}
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETNEIGH;
	nlh->nlmsg_flags = 0;
	ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg));
	ndm->ndm_family = family;
	ndm->ndm_ifindex = ifindex;
	ndm->ndm_state = state;
	ndm->ndm_flags = ndm_flags;
	if (!mnl_attr_put_check(nlh, MNL_SOCKET_BUFFER_SIZE, NDA_LLADDR, 6, mac)) {
		fail("unable to put lladdr");
	}
	if (!mnl_attr_put_u32_check(nlh, MNL_SOCKET_BUFFER_SIZE, NDA_DST, ip4)) {
		fail("unable to put dst");
	}

	memset(&actual_hdata, 0x00, sizeof(struct neighbour_history_data));

	memcpy(&expected_hdata, &actual_hdata, sizeof(struct neighbour_history_data));
	expected_hdata.ndm_state = state;

	if (get_neighbour_header_cb(nlh, tdata) != sizeof(struct ndmsg)) {
		fail("get_neighbour_header_cb returned the wrong size");
	} else {
		pass("get_neighbour_header_cb returned the expected size");
	}

	if (actual_nhdata.ndm_ifindex != ifindex || actual_nhdata.ndm_family != family) {
		fail("nohistory_data did not match");
	} else {
		pass("nohistory_data appeared to be fine");
	}

	if (memcmp(&actual_hdata, &expected_hdata, sizeof(struct neighbour_history_data)) != 0) {
		char* diff = bindiff((unsigned char*)&expected_hdata, (unsigned char*)&actual_hdata, sizeof(struct neighbour_history_data), 0);
		fail("history_data did not match");
		note("\n%s", diff);
		free(diff);
	} else {
		pass("history_data matches");
	}
}

void test_neighbour_prepare_data_tracker()
{
	note("running test_neighbour_prepare_data_tracker");

	struct neighbour_history_data* actual_hdata;
	struct neighbour_nohistory_data* actual_nhdata;
	struct neighbour_history_data expected_hdata;
	struct data_tracker* tracker;

	struct nlmsghdr* nlh = NULL;
	struct ndmsg* ndm = NULL;
	unsigned char buf[MNL_SOCKET_BUFFER_SIZE];
	unsigned int i = 0;
	const uint8_t family = AF_INET;
	const int ifindex = 1;
	const uint8_t state = NUD_REACHABLE | NUD_STALE;
	const uint8_t ndm_flags = 0;
	const unsigned char mac[6] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB};
	const uint32_t ip4 = htonl(0xC0A80001);
	srandom(time(NULL));
	for (i = 0; i < MNL_SOCKET_BUFFER_SIZE; i++) {
		buf[i] = (unsigned char)(((unsigned long int)random()) % 8);
	}
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = 0;
	ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg));
	ndm->ndm_family = family;
	ndm->ndm_ifindex = ifindex;
	ndm->ndm_state = state;
	ndm->ndm_flags = ndm_flags;
	if (!mnl_attr_put_check(nlh, MNL_SOCKET_BUFFER_SIZE, NDA_LLADDR, 6, mac)) {
		fail("unable to put ndm_lladdr");
	}
	if (!mnl_attr_put_u32_check(nlh, MNL_SOCKET_BUFFER_SIZE, NDA_DST, ip4)) {
		fail("unable to put ndm_dst");
	}

	memset(&expected_hdata, 0x00, sizeof(struct neighbour_history_data));

	expected_hdata.ndm_state = state;
	expected_hdata.ndm_flags = ndm_flags;

	if ((tracker = prepare_data_tracker(neighbour_data_size, nlh, &get_neighbour_header_cb, &get_neighbour_attr_cb)) == NULL) {
		fail("prepare_data_tracker returned NULL");
	} else {
		struct tracked_data tdata = get_tracked_data(tracker);
		actual_nhdata = (struct neighbour_nohistory_data*)(tdata.nohistory_data);
		actual_hdata = (struct neighbour_history_data*)(tdata.history_data);
		if (actual_nhdata == NULL || actual_hdata == NULL) {
			fail("received NULL actual data");
		} else {
			pass("actual data returned non-NULL");
		}
	}

	if (actual_nhdata->ndm_ifindex != ifindex || actual_nhdata->addr.ip4.s_addr != ip4 || actual_nhdata->ndm_family != family || memcmp(actual_nhdata->mac, mac, 6) != 0) {
		fail("nohistory_data did not match");
	} else {
		pass("nohistory_data appeared to be fine");
	}

	if (memcmp(actual_hdata, &expected_hdata, sizeof(struct neighbour_history_data)) != 0) {
		char* diff = bindiff((unsigned char*)&expected_hdata, (unsigned char*)actual_hdata, sizeof(struct neighbour_history_data), 0);
		fail("history_data did not match");
		note("\n%s", diff);
		free(diff);
	} else {
		pass("history_data matches");
	}

	abort_data_tracker(tracker);
}

void test_print_neighbour()
{
	note("running test_print_neighbour");

	const struct neighbour_history_data hdata =
	{
		.ndm_state = NUD_REACHABLE | NUD_STALE,
		.ndm_flags = 0,
		.local = false
	};
	const struct neighbour_nohistory_data nhdata =
	{
		.addr = {.ip4 = htonl(0xC0A80001)},
		.ndm_ifindex = 1,
		.ndm_family = AF_INET,
		.mac = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB}
	};
	const struct tracked_data data =
	{
		.nohistory_data = (void*)&nhdata,
		.history_data = (void*)&hdata
	};
	FILE* stream = tmpfile();

	const char* expected = "\"family\":\"AF_INET\",\"iface\":\"eth1\","
		"\"reachable\":1,\"stale\":1,\"ndm_type\":\"0x00\","
		"\"ipaddress\":\"192.168.0.1\",\"mac\":\"01:23:45:67:89:AB\","
		"\"confirmed\":0,\"used\":0,\"updated\":0,\"refcnt\":0,";
	char actual[BUFSIZ];

	print_neighbour(stream, data);

	rewind(stream);

	if (fgets(actual, BUFSIZ, stream) == NULL) {
		fail("unable to fgets");
	}

	fclose(stream);

	if (strncmp(expected, actual, BUFSIZ) != 0) {
		fail("print_neighbour did not match");
		note("expected: %s", expected);
		note("actual: %s", actual);
	} else {
		pass("print_neighbour matched");
	}
}

void test_print_neighbour_diff()
{
	note("running test_print_neighbour_diff");

	const struct neighbour_history_data old_hdata =
	{
		.ndm_state = NUD_REACHABLE | NUD_STALE | NUD_DELAY,
		.ndm_flags = 0,
		.local = false
	};
	const struct neighbour_history_data new_hdata =
	{
		.ndm_state = NUD_FAILED | NUD_PROBE,
		.ndm_flags = 0,
		.ndm_type = 0x21,
		.local = false
	};
	const struct neighbour_nohistory_data nhdata =
	{
		.addr = {.ip4 = htonl(0xC0A80001)},
		.ndm_ifindex = 1,
		.ndm_family = AF_INET,
		.mac = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB}
	};
	const struct tracked_data old_data =
	{
		.nohistory_data = (void*)&nhdata,
		.history_data = (void*)&old_hdata
	};
	const struct tracked_data new_data =
	{
		.nohistory_data = (void*)&nhdata,
		.history_data = (void*)&new_hdata
	};
	FILE* stream = tmpfile();

	const char* expected = "\"reachable\":1,\"stale\":1,\"delay\":1,\"probe\":0,\"failed\":0,\"ndm_type\":\"0x00\",";
	char actual[BUFSIZ];

	print_neighbour_diff(stream, old_data, new_data);

	rewind(stream);

	if (fgets(actual, BUFSIZ, stream) == NULL) {
		fail("unable to fgets");
	}

	fclose(stream);

	if (strncmp(expected, actual, BUFSIZ) != 0) {
		fail("print_neighbour_diff did not match");
		note("expected: %s", expected);
		note("actual: %s", actual);
	} else {
		pass("print_neighbour_diff matched");
	}
}

void test_print_neighbour_data_tracker()
{
	note("running test_print_neighbour_data_tracker");

	struct neighbour_history_data* actual_hdata;
	struct neighbour_nohistory_data* actual_nhdata;
	struct data_tracker* tracker;

	struct nlmsghdr* nlh = NULL;
	struct ndmsg* ndm = NULL;
	unsigned char buf[MNL_SOCKET_BUFFER_SIZE];
	unsigned int i = 0;
	const uint8_t family = AF_INET;
	const int ifindex = 1;
	const uint8_t state = NUD_REACHABLE | NUD_STALE;
	const uint8_t ndm_flags = 0;
	const unsigned char mac[6] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB};
	const uint32_t ip4 = htonl(0xC0A80001);
	srandom(time(NULL));
	for (i = 0; i < MNL_SOCKET_BUFFER_SIZE; i++) {
		buf[i] = (unsigned char)(((unsigned long int)random()) % 8);
	}
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = 0;
	ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg));
	ndm->ndm_family = family;
	ndm->ndm_ifindex = ifindex;
	ndm->ndm_state = state;
	ndm->ndm_flags = ndm_flags;
	if (!mnl_attr_put_check(nlh, MNL_SOCKET_BUFFER_SIZE, NDA_LLADDR, 6, mac)) {
		fail("unable to put ndm_lladdr");
	}
	if (!mnl_attr_put_u32_check(nlh, MNL_SOCKET_BUFFER_SIZE, NDA_DST, ip4)) {
		fail("unable to put ndm_dst");
	}

	if ((tracker = prepare_data_tracker(neighbour_data_size, nlh, &get_neighbour_header_cb, &get_neighbour_attr_cb)) == NULL) {
		fail("prepare_data_tracker returned NULL");
	} else {
		FILE* stream = tmpfile();

		const char* expected = "{\"family\":\"AF_INET\","
			"\"iface\":\"eth1\",\"reachable\":1,\"stale\":1,"
			"\"ndm_type\":\"0x00\",\"ipaddress\":\"192.168.0.1\","
			"\"mac\":\"01:23:45:67:89:AB\",\"confirmed\":0,"
			"\"used\":0,\"updated\":0,\"refcnt\":0,\"last_changed\":";
		char actual[BUFSIZ];

		print_data_tracker(stream, tracker, &print_neighbour, &print_neighbour_diff, NULL);

		rewind(stream);

		if (fgets(actual, BUFSIZ, stream) == NULL) {
			fail("unable to fgets");
		}
	
		fclose(stream);
	
		/*if (strncmp(expected, actual, BUFSIZ) != 0) {*/
		if (strncmp(expected, actual, strnlen(expected, BUFSIZ)) != 0) {
			fail("print_neighbour_data_tracker did not match");
			note("expected: %s", expected);
			note("actual: %s", actual);
		} else {
			pass("print_neighbour_data_tracker matched");
		}
	}
}

int main()
{
	set_configuration(0, NULL);

	test_neighbour_header_cb();

	test_neighbour_prepare_data_tracker();

	test_print_neighbour();

	test_print_neighbour_diff();

	test_print_neighbour_data_tracker();

	return 0;
}

