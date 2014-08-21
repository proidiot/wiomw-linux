#include <config.h>

#include <sysexits.h>
#include <stdlib.h>
#include <dejagnu.h>

#include "../../src/data_tracker.h"

struct data_tracker* make_empty_data_tracker(const struct tracked_data_size size)
{
	xfail("called stub function make_empty_data_tracker");
	exit(EX_UNAVAILABLE);
}

const struct tracked_data get_tracked_data(const struct data_tracker* tracker)
{
	xfail("called stub function get_tracked_data");
	exit(EX_UNAVAILABLE);
}

const char* get_data_index(
		char* index,
		const struct data_tracker* tracker,
		const char* (* index_cb)(char* index, const struct tracked_data data))
{
	xfail("called stub function get_data_index");
	exit(EX_UNAVAILABLE);
}

bool save_data_tracker(
		Pvoid_t* judysl_array,
		pthread_mutex_t* mutex,
		const char* index,
		struct data_tracker* tracker,
		bool (* history_changed_cb)(const struct tracked_data old_data, const struct tracked_data new_data))
{
	xfail("called stub function save_data_tracker");
	exit(EX_UNAVAILABLE);
}

void set_deleted_data(struct data_tracker* tracker)
{
	xfail("called stub function set_deleted_data");
	exit(EX_UNAVAILABLE);
}

struct data_tracker* prepare_data_tracker(
                const struct tracked_data_size size,
                const struct nlmsghdr* nl_hdr,
                size_t (* header_cb)(const struct nlmsghdr* nl_hdr, const struct tracked_data data),
                bool (* attr_cb)(const struct nlattr* nl_attr, const struct tracked_data data))
{
	xfail("called stub function prepare_data_tracker");
	exit(EX_UNAVAILABLE);
}

void clean_data_history(Pvoid_t* judysl_array, pthread_mutex_t* mutex, const size_t index_len)
{
	xfail("called stub function clean_data_history");
	exit(EX_UNAVAILABLE);
}

void print_data_trackers(
                FILE* stream,
                Pvoid_t* judysl_array,
                pthread_mutex_t* mutex,
                void (* print_data)(FILE* stream, const struct tracked_data data),
                void (* print_data_history_diff)(FILE* stream, const struct tracked_data old_data, const struct tracked_data new_data),
                const size_t index_len)
{
	xfail("called stub function print_data_trackersf");
	exit(EX_UNAVAILABLE);
}

bool process_data_from_table(
                void (* process_data_cb)(void* closure, const struct tracked_data),
                void* closure,
                Pvoid_t* judysl_array,
                pthread_mutex_t* mutex,
                const char* index)
{
	xfail("called stub function process_data_cb");
	exit(EX_UNAVAILABLE);
}
