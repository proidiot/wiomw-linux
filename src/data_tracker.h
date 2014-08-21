#ifndef _WIOMW_DATA_TRACKER_H_
#define _WIOMW_DATA_TRACKER_H_

#include <stdbool.h>
#include <time.h>
#include <linux/netlink.h>
#include <Judy.h>
#include <pthread.h>

struct tracked_data {
	void* const nohistory_data;
	void* const history_data;
};

struct tracked_data_size {
	const size_t nohistory_data_len;
	const size_t history_data_len;
};

struct data_tracker* prepare_data_tracker(
		const struct tracked_data_size size,
		const struct nlmsghdr* nl_hdr,
		size_t (* header_cb)(const struct nlmsghdr* nl_hdr, const struct tracked_data data),
		bool (* attr_cb)(const struct nlattr* nl_attr, const struct tracked_data data));

const char* get_data_index(
		char* index,
		const struct data_tracker* tracker,
		const char* (* index_cb)(char* index, const struct tracked_data data));

bool save_data_tracker(
		Pvoid_t* judysl_array,
		pthread_mutex_t* mutex,
		const char* index,
		struct data_tracker* tracker,
		bool (* history_changed_cb)(const struct tracked_data old_data, const struct tracked_data new_data));

void set_deleted_data(struct data_tracker* tracker);

void print_data_trackers(
		FILE* stream,
		Pvoid_t* judysl_array,
		pthread_mutex_t* mutex,
		void (* print_data)(FILE* stream, const struct tracked_data data),
		void (* print_data_history_diff)(FILE* stream, const struct tracked_data old_data, const struct tracked_data new_data),
		const size_t index_len);

void clean_data_history(Pvoid_t* judysl_array, pthread_mutex_t* mutex, const size_t index_len);

bool process_data_from_table(
		void (* process_data_cb)(void* closure, const struct tracked_data),
		void* closure,
		Pvoid_t* judysl_array,
		pthread_mutex_t* mutex,
		const char* index);

const struct tracked_data get_tracked_data(const struct data_tracker* tracker);

struct data_tracker* make_empty_data_tracker(const struct tracked_data_size size);

#endif
