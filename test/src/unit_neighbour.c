#include <config.h>
#include <dejagnu.h>

#include <stdlib.h>
#include <time.h>
#include <libmnl/libmnl.h>

#include "bindiff.h"

#include "../../src/neighbour.c"

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
	unsigned char mac[6];
	unsigned char ip4[4];
	mac[0] = 0x01;
	mac[1] = 0x23;
	mac[2] = 0x45;
	mac[3] = 0x67;
	mac[4] = 0x89;
	mac[5] = 0xAB;
	ip4[0] = 0xC0;
	ip4[1] = 0xA8;
	ip4[2] = 0x00;
	ip4[3] = 0x01;
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
	if (!mnl_attr_put_check(nlh, MNL_SOCKET_BUFFER_SIZE, NDA_DST, 4, ip4)) {
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

int main()
{
	test_neighbour_header_cb();

	return 0;
}

