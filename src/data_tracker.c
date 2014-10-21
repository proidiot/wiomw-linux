#include <config.h>
#include "data_tracker.h"

#include <stdbool.h>
#include <time.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <libmnl/libmnl.h>
#include <Judy.h>
#include <string.h>
#include <syslog.h>
#include <sysexits.h>
#include "syslog_syserror.h"

#define JSON_HISTORY_STRING "history"
#define JSON_TIME_LAST_CHANGED_STRING "last_changed"
#define JSON_TIME_LAST_SEEN_STRING "last_seen"

struct data_history_entry {
	struct data_history_entry* older; /* read locked by read_locked, write locked by read_locked and table mutex */
	struct data_history_entry* newer; /* read locked by read_locked, write locked by read_locked and table mutex */
	time_t time; /* read only */
	bool deleted; /* read only */
	unsigned char history_data[]; /* read/write locked by read_locked */
};

struct data_tracker {
	struct data_history_entry* current; /* read only (could change during initial table insertion) */
	struct data_history_entry* bottom; /* read/write locked by table mutex */
	struct data_history_entry* last_read; /* read/write locked by table mutex */
	struct data_tracker* higher; /* read/write locked by table mutex */
	struct data_tracker* lower; /* read/write locked by table mutex */
	time_t time; /* read only */
	unsigned int older_count; /* count of history entries older than current */
	unsigned int read_older_count; /* count as of the time last read time */
	unsigned int read_locks; /* number of read locks placed on this tracker */
	unsigned char nohistory_data[];
};

const struct tracked_data get_tracked_data(const struct data_tracker* tracker)
{
	const struct tracked_data data =
	{
		.nohistory_data = (void*)&(tracker->nohistory_data),
		.history_data = (void*)&(tracker->current->history_data)
	};
	return data;
}

struct data_tracker* make_empty_data_tracker(const struct tracked_data_size size)
{
	struct data_tracker* const tracker = (struct data_tracker*)malloc(sizeof(struct data_tracker) + size.nohistory_data_len);
	if (tracker == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to malloc");
		exit(EX_OSERR);
	}
	memset(tracker, 0x00, sizeof(struct data_tracker) + size.nohistory_data_len);
	tracker->current = (struct data_history_entry*)malloc(sizeof(struct data_history_entry) + size.history_data_len);
	if (tracker->current == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to malloc");
		exit(EX_OSERR);
	}
	memset(tracker->current, 0x00, sizeof(struct data_history_entry) + size.history_data_len);
	return tracker;
}

struct mnl_attr_cb_closure {
	bool (* const attr_cb)(const struct nlattr* nl_attr, const struct tracked_data data);
	struct data_tracker* const tracker;
};

static int mnl_attr_cb(const struct nlattr* const nl_attr, void* const closure)
{
	const struct mnl_attr_cb_closure* const real_closure = (const struct mnl_attr_cb_closure*)closure;
	const struct tracked_data data =
	{
		.nohistory_data = (void*)&(real_closure->tracker->nohistory_data),
		.history_data = (void*)&(real_closure->tracker->current->history_data)
	};
	if (!real_closure->attr_cb(nl_attr, data)) {
		return MNL_CB_ERROR;
	} else {
		return MNL_CB_OK;
	}
}

static void abort_data_tracker(struct data_tracker* tracker)
{
	free(tracker->current);
	free(tracker);
	return;
}

struct data_tracker* prepare_data_tracker(
		const struct tracked_data_size size,
		const struct nlmsghdr* nl_hdr,
		size_t (* const header_cb)(const struct nlmsghdr* nl_hdr, const struct tracked_data data),
		bool (* const attr_cb)(const struct nlattr* nl_attr, const struct tracked_data data))
{
	const time_t now = time(NULL);
	size_t nl_offset = 0;
	struct data_tracker* const tracker = make_empty_data_tracker(size);
	const struct mnl_attr_cb_closure closure = 
	{
		.attr_cb = attr_cb,
		.tracker = tracker
	};
	const struct tracked_data data =
	{
		.nohistory_data = (void*)&(tracker->nohistory_data),
		.history_data = (void*)&(tracker->current->history_data)
	};

	if ((nl_offset = header_cb(nl_hdr, data)) == 0) {
		abort_data_tracker(tracker);
		return NULL;
	}

	if (mnl_attr_parse(nl_hdr, nl_offset, &mnl_attr_cb, (void*)&closure) == MNL_CB_ERROR) {
		abort_data_tracker(tracker);
		return NULL;
	}

	tracker->time = now;
	tracker->read_locks = 0;
	tracker->bottom = tracker->current;
	tracker->last_read = NULL;
	tracker->higher = tracker;
	tracker->lower = NULL;
	tracker->older_count = 0;
	tracker->read_older_count = 0;
	tracker->current->time = now;
	tracker->current->older = NULL;
	tracker->current->newer = NULL;
	tracker->current->deleted = false;

	return tracker;
}

const char* get_data_index(
		char* index,
		const struct data_tracker* tracker,
		const char* (* const index_cb)(char* index, const struct tracked_data data))
{
	const struct tracked_data data = 
	{
		.nohistory_data = (void*)&(tracker->nohistory_data),
		.history_data = (void*)&(tracker->current->history_data)
	};
	return index_cb(index, data);
}

bool save_data_tracker(
		Pvoid_t* judysl_array,
		pthread_mutex_t* mutex,
		const char* index,
		struct data_tracker* tracker,
		bool (* const history_changed_cb)(const struct tracked_data old_data, const struct tracked_data new_data))
{
	Word_t* temporary_judy_entry_pointer = NULL;
	struct data_tracker* lower = NULL;
	bool read_locked = false;
	bool lower_was_read_locked = false;
	struct data_history_entry* freeable_entry = NULL;

	const struct tracked_data newer_data =
	{
		.nohistory_data = (void*)&(tracker->nohistory_data),
		.history_data = (void*)&(tracker->current->history_data)
	};

	/* Begin critical section */
	pthread_mutex_lock(mutex);

	JSLI(temporary_judy_entry_pointer, *judysl_array, (const uint8_t*)index);

	if ((struct data_tracker*)*temporary_judy_entry_pointer != NULL) {
		lower = (struct data_tracker*)*temporary_judy_entry_pointer;
		const struct tracked_data older_data =
		{
			.nohistory_data = (void*)&(tracker->nohistory_data),
			.history_data = (void*)&(lower->current->history_data)
		};

		if (history_changed_cb(older_data, newer_data)) {
			tracker->current->older = lower->current;
			lower->current->newer = tracker->current;
	
			if ((read_locked = (lower->read_locks > 0))) {
				tracker->lower = lower;
				lower->higher = tracker;
				lower_was_read_locked = true;
			} else if ((read_locked = (lower->lower != NULL))) {
				tracker->lower = lower->lower;
				lower->lower->higher = tracker;
			}
	
			if (lower->older_count + 1 >= CONFIG_OPTION_HISTORY_DEPTH) {
				tracker->bottom = lower->bottom->newer;
				if (lower->last_read == lower->bottom) {
					tracker->last_read = tracker->bottom;
				} else {
					tracker->last_read = lower->last_read;
				}
				if (read_locked) {
					tracker->lower->bottom = tracker->bottom;
				} else {
					freeable_entry = lower->bottom;
					tracker->bottom->older = NULL;
				}
				tracker->older_count = CONFIG_OPTION_HISTORY_DEPTH - 1;
				if (lower->read_older_count > 0) {
					tracker->read_older_count = lower->read_older_count - 1;
				}
			} else {
				tracker->bottom = lower->bottom;
				tracker->older_count = lower->older_count + 1;
				tracker->read_older_count = lower->read_older_count;
				tracker->last_read = lower->last_read;
			}
		} else {
			freeable_entry = tracker->current;
			tracker->current = lower->current;
			tracker->bottom = lower->bottom;
			tracker->older_count = lower->older_count;
			tracker->last_read = lower->last_read;
			tracker->read_older_count = lower->read_older_count;
		}
	}

	*temporary_judy_entry_pointer = (Word_t)tracker;

	pthread_mutex_unlock(mutex);
	/* End critical section */

	if (freeable_entry != NULL) {
		free(freeable_entry);
	}

	if (lower != NULL && !lower_was_read_locked) {
		free(lower);
	}

	return true;
}

void set_deleted_data(struct data_tracker* tracker)
{
	tracker->current->deleted = true;
	return;
}

static bool in_critical_read_clean(
		struct data_tracker* const tracker,
		struct data_tracker** higher_tracker,
		struct data_history_entry** new_bottom)
{
	bool read_locked;
	if (tracker != NULL) {
		if ((*higher_tracker = tracker->higher) != NULL) {
			if ((*higher_tracker)->last_read == tracker->last_read) {
				(*higher_tracker)->last_read = tracker->current;
			}
			(*higher_tracker)->lower = tracker->lower;
		} else {
			/* probably won't be needed as the tracker itself is set to be removed from the table, but won't hurt */
			tracker->last_read = tracker->current;
		}
		*new_bottom = tracker->bottom;
		if ((read_locked = tracker->lower != NULL)) {
			tracker->lower->bottom = tracker->bottom;
			tracker->lower->higher = *higher_tracker;
		}
		tracker->read_locks--;
	}
	return read_locked;
}

static void out_critical_read_clean(
		struct data_tracker* const tracker,
		const struct data_tracker* const higher_tracker,
		const bool read_locked,
		struct data_history_entry* old_bottom,
		const struct data_history_entry* const new_bottom)
{
	if (!read_locked) {
		while (old_bottom != new_bottom) {
			struct data_history_entry* temp = old_bottom;
			old_bottom = old_bottom->newer;
			free(temp);
		}
	}

	if (tracker != higher_tracker) {
		free(tracker);
	}
	return;
}

void print_data_tracker(
		FILE* stream,
		const struct data_tracker* tracker,
		void (* print_data)(FILE* stream, const struct tracked_data data),
		void (* print_data_history_diff)(FILE* stream, const struct tracked_data old_data, const struct tracked_data new_data),
		const struct data_history_entry* bottom)
{
			const struct tracked_data data = 
			{
				.nohistory_data = (void*)&(tracker->nohistory_data),
				.history_data = (void*)&(tracker->current->history_data)
			};

			fprintf(stream, "{");

			print_data(stream, data);

			if (bottom !=  NULL && bottom != tracker->current) {
				struct data_history_entry* newer = tracker->current;
				fprintf(stream, "\""JSON_HISTORY_STRING"\":[{");
				do {
					struct data_history_entry* older = newer->older;
					const struct tracked_data older_data =
					{
						.nohistory_data = (void*)&(tracker->nohistory_data),
						.history_data = (void*)&(older->history_data)
					};
					const struct tracked_data newer_data =
					{
						.nohistory_data = (void*)&(tracker->nohistory_data),
						.history_data = (void*)&(newer->history_data)
					};
					print_data_history_diff(stream, older_data, newer_data);
					fprintf(stream, "\""JSON_TIME_LAST_CHANGED_STRING"\":%ld", older->time);
					if ((newer = older) != bottom) {
						fprintf(stream, "},{");
					}
				} while (newer != bottom);
				fprintf(stream, "}],");
			}

			fprintf(
					stream,
					"\""JSON_TIME_LAST_CHANGED_STRING"\":%ld,\""JSON_TIME_LAST_SEEN_STRING"\":%ld}",
					tracker->current->time,
					tracker->time);
}

void print_data_trackers(
		FILE* stream,
		Pvoid_t* judysl_array,
		pthread_mutex_t* mutex,
		void (* print_data)(FILE* stream, const struct tracked_data data),
		void (* print_data_history_diff)(FILE* stream, const struct tracked_data old_data, const struct tracked_data new_data),
		const size_t index_len)
{
	struct data_tracker* tracker = NULL;
	struct data_history_entry* saved_bottom = NULL;
	uint8_t index_buffer[index_len + 1];
	index_buffer[0] = '\0';

	do {
		Word_t* temporary_judy_entry_pointer = NULL;
		struct data_history_entry* old_bottom = saved_bottom;
		struct data_history_entry* new_bottom = old_bottom;
		struct data_tracker* higher = NULL;
		struct data_tracker* old_tracker = tracker;
		unsigned int count = 0;
		bool read_locked = false;
		bool deleted = false;

		/* Begin critical section */
		pthread_mutex_lock(mutex);

		read_locked = in_critical_read_clean(old_tracker, &higher, &new_bottom);

		JSLN(temporary_judy_entry_pointer, *judysl_array, index_buffer);
		if (temporary_judy_entry_pointer != NULL && (struct data_tracker*)*temporary_judy_entry_pointer != NULL) {
			tracker = (struct data_tracker*)*temporary_judy_entry_pointer;
			tracker->read_locks++;
			saved_bottom = tracker->bottom;
			count = tracker->older_count;
			tracker->read_older_count = tracker->older_count;
			deleted = tracker->current->deleted;
		} else {
			tracker = NULL;
		}

		pthread_mutex_unlock(mutex);
		/* End critical section */

		out_critical_read_clean(old_tracker, higher, read_locked, old_bottom, new_bottom);

		if (tracker != NULL && (!deleted || count > 0)) {
			if (old_tracker != NULL) {
				fprintf(stream, ",");
			}
			print_data_tracker(stream, tracker, print_data, print_data_history_diff, (count == 0)? tracker->current : saved_bottom);
			/*
			const struct tracked_data data = 
				{
					.nohistory_data = (void*)&(tracker->nohistory_data),
					.history_data = (void*)&(tracker->current->history_data)
				};
			if (old_tracker == NULL) {
				fprintf(stream, "{");
			} else {
				fprintf(stream, ",{");
			}

			print_data(stream, data);

			if (count > 0) {
				struct data_history_entry* newer = tracker->current;
				fprintf(stream, "\""JSON_HISTORY_STRING"\":[{");
				while (newer != saved_bottom) {
					struct data_history_entry* older = newer->older;
					const struct tracked_data older_data =
						{
							.nohistory_data = (void*)&(tracker->nohistory_data),
							.history_data = (void*)&(older->history_data)
						};
					const struct tracked_data newer_data =
						{
							.nohistory_data = (void*)&(tracker->nohistory_data),
							.history_data = (void*)&(newer->history_data)
						};
					print_data_history_diff(stream, older_data, newer_data);
					fprintf(stream, "\""JSON_TIME_LAST_CHANGED_STRING"\":\"%s\"", ctime(&(older->time)));
					if ((newer = older) != saved_bottom) {
						fprintf(stream, "},{");
					}
				}
				fprintf(stream, "}],");
			}

			fprintf(
					stream,
					"\""JSON_TIME_LAST_CHANGED_STRING"\":\"%s\",\""JSON_TIME_LAST_SEEN_STRING"\":\"%s\"}",
					ctime(&(tracker->current->time)),
					ctime(&(tracker->time)));
			*/
		}
	} while (tracker != NULL);
	return;
}

void clean_data_history(Pvoid_t* judysl_array, pthread_mutex_t* mutex, const size_t index_len)
{
	struct data_tracker* tracker = NULL;
	uint8_t index_buffer[index_len + 1];
	index_buffer[0] = '\0';

	do {
		Word_t* temporary_judy_entry_pointer = NULL;
		struct data_history_entry* bottom = NULL;
		struct data_history_entry* last_read = NULL;
		bool read_locked = false;
		bool deleted = false;

		/* Begin critical section */
		pthread_mutex_lock(mutex);

		JSLN(temporary_judy_entry_pointer, *judysl_array, index_buffer);
		if (temporary_judy_entry_pointer != NULL && (struct data_tracker*)*temporary_judy_entry_pointer != NULL) {
			tracker = (struct data_tracker*)*temporary_judy_entry_pointer;
			last_read = tracker->last_read;
			if ((read_locked = (tracker->read_locks > 0))) {
				tracker->bottom = last_read;
			} else if ((read_locked = tracker->lower != NULL)) {
				tracker->lower->bottom = last_read;
			}
			if (last_read == tracker->current && (deleted = tracker->current->deleted) && !CONFIG_OPTION_DEFER_DELETE) {
				int status = 0;
				JSLD(status, *judysl_array, index_buffer);
				tracker->higher = NULL;
			} else {
				if (!read_locked) {
					last_read->older = NULL;
				}
				bottom = tracker->bottom;
				tracker->older_count -= tracker->read_older_count;
				tracker->read_older_count = 0;
			}
		} else {
			tracker = NULL;
		}

		pthread_mutex_unlock(mutex);
		/* End critical section */

		if (!read_locked && last_read != NULL) {
			if (!CONFIG_OPTION_DEFER_DELETE && deleted) {
				while (last_read != NULL) {
					struct data_history_entry* temp = last_read;
					last_read = last_read->older;
					free(temp);
				}
				free(tracker);
			} else  {
				while (bottom != last_read) {
					struct data_history_entry* temp = bottom;
					bottom = bottom->newer;
					free(temp);
				}
			}
		}
	} while (tracker != NULL);
	return;
}

bool process_data_from_table(
		void (* const process_data_cb)(void* closure, const struct tracked_data data),
		void* closure,
		Pvoid_t* judysl_array,
		pthread_mutex_t* mutex,
		const char* index)
{
	struct data_tracker* tracker = NULL;
	struct data_tracker* higher = NULL;
	struct data_history_entry* new_bottom = NULL;
	struct data_history_entry* old_bottom = NULL;
	bool read_locked = false;
	Word_t* temporary_judy_entry_pointer = NULL;

	/* Begin critical section */
	pthread_mutex_lock(mutex);

	JSLG(temporary_judy_entry_pointer, *judysl_array, (const uint8_t*)index);
	if (temporary_judy_entry_pointer != NULL && (struct data_tracker*)*temporary_judy_entry_pointer != NULL) {
		tracker = (struct data_tracker*)*temporary_judy_entry_pointer;
		tracker->read_locks++;
		old_bottom = tracker->bottom;
	} else {
		tracker = NULL;
	}

	pthread_mutex_unlock(mutex);
	/* End critical section */

	const struct tracked_data data = 
	{
		.nohistory_data = (void*)&(tracker->nohistory_data),
		.history_data = (void*)&(tracker->current->history_data)
	};
	process_data_cb(closure, data);

	/* Begin critical section */
	pthread_mutex_lock(mutex);

	read_locked = in_critical_read_clean(tracker, &higher, &new_bottom);

	pthread_mutex_unlock(mutex);
	/* End critical section */

	out_critical_read_clean(tracker, higher, read_locked, old_bottom, new_bottom);

	return true;
}

