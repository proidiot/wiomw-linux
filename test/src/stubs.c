#include <config.h>

#include <sysexits.h>
#include <stdlib.h>
#include <syslog.h>
#include "../../src/ip.h"
#include "../../src/data_tracker.h"

int add_ifaddr_entry(const int index, const unsigned char family, const union ip addr, const unsigned char* mac)
{
	syslog(LOG_ALERT, "called stub function add_ifaddr_entry");
	exit(EX_UNAVAILABLE);
}

void get_iface_name(char* name, const int ifindex)
{
	syslog(LOG_ALERT, "called stub function get_iface_name");
	exit(EX_UNAVAILABLE);
}

struct data_tracker* make_empty_data_tracker(const struct tracked_data_size size)
{
	syslog(LOG_ALERT, "called stub function make_empty_data_tracker");
	exit(EX_UNAVAILABLE);
}

const struct tracked_data get_tracked_data(const struct data_tracker* tracker)
{
	syslog(LOG_ALERT, "called stub function get_tracked_data");
	exit(EX_UNAVAILABLE);
}

const char* get_data_index(
		char* index,
		const struct data_tracker* tracker,
		const char* (* index_cb)(char* index, const struct tracked_data data))
{
	syslog(LOG_ALERT, "called stub function get_data_index");
	exit(EX_UNAVAILABLE);
}

bool save_data_tracker(
		Pvoid_t* judysl_array,
		pthread_mutex_t* mutex,
		const char* index,
		struct data_tracker* tracker,
		bool (* history_changed_cb)(const struct tracked_data old_data, const struct tracked_data new_data))
{
	syslog(LOG_ALERT, "called stub function save_data_tracker");
	exit(EX_UNAVAILABLE);
}


