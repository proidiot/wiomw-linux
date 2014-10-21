#include <config.h>
#include <dejagnu.h>

#include <string.h>
#include "../../src/mnl_helpers.h"

#include "../../src/data_tracker.c"

#define NH_HEADER_LEN 2
#define NH_ATTR_LEN 2
#define TH_HEADER_LEN 2
#define TH_ATTR_LEN 2

struct test_nohistory_data {
	unsigned char nh_header[NH_HEADER_LEN];
	unsigned char nh_attr[NH_ATTR_LEN];
};

struct test_history_data {
	unsigned char th_header[TH_HEADER_LEN];
	unsigned char th_attr[TH_ATTR_LEN];
};

const struct tracked_data_size test_data_size =
{
	.nohistory_data_len = sizeof(struct test_nohistory_data),
	.history_data_len = sizeof(struct test_history_data)
};

struct test_nlmsg {
	unsigned char nh_data[NH_HEADER_LEN];
	unsigned char th_data[TH_HEADER_LEN];
};

enum {
	TEST_NLA_NH,
	TEST_NLA_TH
};

#define TEST_NLA_MAX TEST_NLA_TH

size_t test_header_cb(const struct nlmsghdr* nlh, const struct tracked_data data)
{
	struct test_nohistory_data* nhd = (struct test_nohistory_data*)data.nohistory_data;
	struct test_history_data* hd = (struct test_history_data*)data.history_data;

	memset(hd, 0x00, sizeof(struct test_history_data));

	const struct test_nlmsg* nlm = (const struct test_nlmsg*)mnl_nlmsg_get_payload(nlh);

	memcpy(nhd->nh_header, nlm->nh_data, NH_HEADER_LEN);
	memcpy(hd->th_header, nlm->th_data, TH_HEADER_LEN);

	return sizeof(struct test_nlmsg);
}

bool test_attr_cb(const struct nlattr* nla, const struct tracked_data data)
{
	struct test_nohistory_data* nhd = (struct test_nohistory_data*)data.nohistory_data;
	struct test_history_data* hd = (struct test_history_data*)data.history_data;

	if (mnl_attr_type_valid(nla, TEST_NLA_MAX) < 0) {
		return false;
	}

	switch (mnl_attr_get_type(nla)) {
	case TEST_NLA_NH:
		if (mnl_attr_copy_binary(nhd->nh_attr, nla, NH_ATTR_LEN) < 0) {
			return false;
		}
		break;
	case TEST_NLA_TH:
		if (mnl_attr_copy_binary(hd->th_attr, nla, TH_ATTR_LEN) < 0) {
			return false;
		}
		break;
	}
	return true;
}

void test_prepare_data_tracker()
{
	note("running test_prepare_data_tracker");

	struct nlmsghdr* nlh = NULL;
	struct test_nlmsg* nlm = NULL;
	unsigned char buf[MNL_SOCKET_BUFFER_SIZE];
	unsigned int i = 0;
	unsigned char nh_attr[NH_ATTR_LEN];
	unsigned char th_attr[TH_ATTR_LEN];
	srandom(time(NULL));
	for (i = 0; i < MNL_SOCKET_BUFFER_SIZE; i++) {
		buf[i] = (unsigned char)(((unsigned long int)random()) % 8);
	}
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = 1;
	nlh->nlmsg_flags = 0;
	nlm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct test_nlmsg));
	for (i = 0; i < NH_HEADER_LEN; i++) {
		nlm->nh_data[i] = (unsigned char)(((unsigned long int)random()) % 8);
	}
	for (i = 0; i < TH_HEADER_LEN; i++) {
		nlm->th_data[i] = (unsigned char)(((unsigned long int)random()) % 8);
	}
	for (i = 0; i < NH_ATTR_LEN; i++) {
		nh_attr[i] = (unsigned char)(((unsigned long int)random()) % 8);
	}
	if (!mnl_attr_put_check(nlh, MNL_SOCKET_BUFFER_SIZE, TEST_NLA_NH, NH_ATTR_LEN, nh_attr)) {
		fail("unable to put nh_attr");
	}
	for (i = 0; i < TH_ATTR_LEN; i++) {
		th_attr[i] = (unsigned char)(((unsigned long int)random()) % 8);
	}
	if (!mnl_attr_put_check(nlh, MNL_SOCKET_BUFFER_SIZE, TEST_NLA_TH, TH_ATTR_LEN, th_attr)) {
		fail("unable to put th_attr");
	}

	const struct data_history_entry expected_dhe =
	{
		.older = NULL,
		.deleted = false
	};
	const struct data_tracker expected_tracker =
	{
		.last_read = NULL,
		.lower = NULL,
		.older_count = 0,
		.read_older_count = 0,
		.read_locks = 0
	};


	struct data_tracker* actual_tracker = prepare_data_tracker(
			test_data_size,
			nlh,
			&test_header_cb,
			&test_attr_cb);
	struct data_history_entry* actual_dhe;

	if (actual_tracker == NULL) {
		fail("prepare_data_tracker returned NULL");
	} else if ((actual_dhe = actual_tracker->current) == NULL) {
		fail("prepare_data_tracker returned a NULL history");
	} else if (actual_tracker->bottom != actual_dhe) {
		fail("current history is not bottom as expected");
	} else if (actual_tracker->higher != actual_tracker) {
		fail("top tracker is not listed as its own higher");
	} else if (actual_tracker->last_read != expected_tracker.last_read
			|| actual_tracker->older_count != expected_tracker.older_count
			|| actual_tracker->read_older_count != expected_tracker.read_older_count
			|| actual_tracker->read_locks != expected_tracker.read_locks) {
		fail("actual tracker properties do not match expected");
	} else if (actual_dhe->older != expected_dhe.older
			|| actual_dhe->deleted != expected_dhe.deleted) {
		fail("actual data history properties do not match expected");
	} else if (memcmp(((struct test_nohistory_data*)(actual_tracker->nohistory_data))->nh_header, nlm->nh_data, NH_HEADER_LEN) != 0) {
		fail("actual nohistory header test data does not match expected");
	} else if (memcmp(((struct test_history_data*)(actual_dhe->history_data))->th_header, nlm->th_data, TH_HEADER_LEN) != 0) {
		fail("actual history header test data does not match expected");
	} else if (memcmp(((struct test_nohistory_data*)(actual_tracker->nohistory_data))->nh_attr, nh_attr, NH_ATTR_LEN) != 0) {
		fail("actual nohistory attribute test data does not match expected");
	} else if (memcmp(((struct test_history_data*)(actual_dhe->history_data))->th_attr, th_attr, TH_ATTR_LEN) != 0) {
		fail("actual history attribute test data does not match expected");
	} else {
		pass("prepare_data_tracker returned a valid data tracker");
	}

	abort_data_tracker(actual_tracker);
}

int main()
{
	test_prepare_data_tracker();

	return 0;
}

