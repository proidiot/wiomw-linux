#include <config.h>
#include "neighbour.h"
#include <stdbool.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <syslog.h>
#include <Judy.h>
#include "syslog_syserror.h"
#include "ip.h"
#include "iface.h"
#include "data_tracker.h"
#include "mnl_helpers.h"

#define NEIGHBOUR_INDEX_LENGTH ((sizeof(int) * 2) + 1 + 12 + 32 + 1)

#define JSON_NUD_INCOMPLETE_STRING "incomplete"
#define JSON_NUD_REACHABLE_STRING "reachable"
#define JSON_NUD_STALE_STRING "stale"
#define JSON_NUD_DELAY_STRING "delay"
#define JSON_NUD_PROBE_STRING "probe"
#define JSON_NUD_FAILED_STRING "failed"
#define JSON_NUD_NOARP_STRING "noarp"
#define JSON_NUD_PERMANENT_STRING "permanent"
#define JSON_NTF_PROXY_STRING "proxu"
#define JSON_NTF_ROUTER_STRING "ip6router"
#define JSON_NDM_TYPE_STRING "ndm_type"
#define JSON_NDM_FAMILY_STRING "family"
#define JSON_NDM_CONFIRMED_STRING "confirmed"
#define JSON_NDM_USED_STRING "used"
#define JSON_NDM_UPDATED_STRING "updated"
#define JSON_NDM_REFCNT_STRING "refcnt"
#define JSON_NDA_DST_IPV4_STRING "ipaddress"
#define JSON_NDA_DST_IPV6_STRING "ip6"
#define JSON_NDA_LLADDR_STRING "mac"
#define JSON_AGENT_STRING "agent"
#define JSON_IFACE_NAME_STRING "iface"


#define JSON_ADDR_STRING(af, which) (af == AF_INET)?"\""JSON_##which##_IPV4_STRING"\":\"%s\",":"\""JSON_##which##_IPV6_STRING"\":\"%s\","

struct neighbour_history_data {
	uint16_t ndm_state;
	uint8_t ndm_flags;
	uint8_t ndm_type;
	bool local;
};

struct neighbour_nohistory_data {
	union ip addr;
	struct nda_cacheinfo stats;
	int ndm_ifindex;
	unsigned char ndm_family;
	unsigned char mac[6];
};

static const struct tracked_data_size neighbour_data_size =
	{
		nohistory_data_len: sizeof(struct neighbour_nohistory_data),
		history_data_len: sizeof(struct neighbour_history_data)
	};

static Pvoid_t neighbour_table = (Pvoid_t)NULL;
/*static pthread_mutex_t neighbour_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;*/
static pthread_mutex_t neighbour_mutex = PTHREAD_MUTEX_INITIALIZER;

static void print_neighbour_ndm_state(FILE* stream, const uint16_t target, const uint16_t reference)
{
	uint16_t tstate = target ^ reference;
	if (tstate == 0) {
		return;
	}
	if (tstate & NUD_INCOMPLETE) {
		fprintf(stream, "\""JSON_NUD_INCOMPLETE_STRING"\":%d,", (target & NUD_INCOMPLETE) != 0);
	}
	if (tstate & NUD_REACHABLE) {
		fprintf(stream, "\""JSON_NUD_REACHABLE_STRING"\":%d,", (target & NUD_REACHABLE) != 0);
	}
	if (tstate & NUD_STALE) {
		fprintf(stream, "\""JSON_NUD_STALE_STRING"\":%d,", (target & NUD_STALE) != 0);
	}
	if (tstate & NUD_DELAY) {
		fprintf(stream, "\""JSON_NUD_DELAY_STRING"\":%d,", (target & NUD_DELAY) != 0);
	}
	if (tstate & NUD_PROBE) {
		fprintf(stream, "\""JSON_NUD_PROBE_STRING"\":%d,", (target & NUD_PROBE) != 0);
	}
	if (tstate & NUD_FAILED) {
		fprintf(stream, "\""JSON_NUD_FAILED_STRING"\":%d,", (target & NUD_FAILED) != 0);
	}
	if (tstate & NUD_NOARP) {
		fprintf(stream, "\""JSON_NUD_NOARP_STRING"\":%d,", (target & NUD_NOARP) != 0);
	}
	if (tstate & NUD_PERMANENT) {
		fprintf(stream, "\""JSON_NUD_PERMANENT_STRING"\":%d,", (target & NUD_PERMANENT) != 0);
	}
}

static void print_neighbour_ndm_flags(FILE* stream, const uint8_t target, const uint8_t reference)
{
	uint8_t tflags = target ^ reference;
	if (tflags == 0) {
		return;
	}
	if (tflags & NTF_PROXY) {
		fprintf(stream, "\""JSON_NTF_PROXY_STRING"\":%d,", (target & NTF_PROXY) != 0);
	}
	if (tflags & NTF_ROUTER) {
		fprintf(stream, "\""JSON_NTF_ROUTER_STRING"\":%d,", (target & NTF_ROUTER) != 0);
	}
}

static void print_neighbour_diff(FILE* stream, const struct tracked_data old_data, const struct tracked_data new_data)
{
	const struct neighbour_history_data* const old = (const struct neighbour_history_data*)old_data.history_data;
	const struct neighbour_history_data* const new = (const struct neighbour_history_data*)new_data.history_data;
	print_neighbour_ndm_state(stream, old->ndm_state, new->ndm_state);
	print_neighbour_ndm_flags(stream, old->ndm_flags, new->ndm_flags);
	if (old->ndm_type != new->ndm_type) {
		fprintf(stream, "\""JSON_NDM_TYPE_STRING"\":\"0x%02X\",", old->ndm_type);
	}
	if (old->local != new->local) {
		syslog(LOG_ERR, "Address is showing up as both local and a neighbour");
		if (old->local) {
			fprintf(stream, "\""JSON_AGENT_STRING"\":1,");
		}
	}
}

static void print_neighbour(FILE* stream, const struct tracked_data data)
{
	const struct neighbour_nohistory_data* const neighbour = (const struct neighbour_nohistory_data* const)data.nohistory_data;
	const struct neighbour_history_data* const current = (const struct neighbour_history_data* const)data.history_data;
	/*const struct data_history_entry* tdata = NULL;*/
	char temp[BUFSIZ];
	if (current->local) {
		fprintf(stream, "\""JSON_AGENT_STRING"\":1,");
	}
	fprintf(stream, "\""JSON_NDM_FAMILY_STRING"\":\"%s\",", (neighbour->ndm_family == AF_INET)? "AF_INET" : "AF_INET6");
	get_iface_name(temp, neighbour->ndm_ifindex);
	fprintf(stream, "\""JSON_IFACE_NAME_STRING"\":\"%s\",", temp);
	print_neighbour_ndm_state(stream, current->ndm_state, 0);
	print_neighbour_ndm_flags(stream, current->ndm_flags, 0);
	fprintf(stream, "\""JSON_NDM_TYPE_STRING"\":\"0x%02X\",", current->ndm_type);
	snprint_ip(temp, BUFSIZ, neighbour->ndm_family, neighbour->addr);
	fprintf(stream, JSON_ADDR_STRING(neighbour->ndm_family, NDA_DST), temp);
	fprintf(stream,
		"\""JSON_NDA_LLADDR_STRING"\":\"%02X:%02X:%02X:%02X:%02X:%02X\",",
		neighbour->mac[0],
		neighbour->mac[1],
		neighbour->mac[2],
		neighbour->mac[3],
		neighbour->mac[4],
		neighbour->mac[5]);
	fprintf(stream, "\""JSON_NDM_CONFIRMED_STRING"\":%d,", neighbour->stats.ndm_confirmed);
	fprintf(stream, "\""JSON_NDM_USED_STRING"\":%d,", neighbour->stats.ndm_used);
	fprintf(stream, "\""JSON_NDM_UPDATED_STRING"\":%d,", neighbour->stats.ndm_updated);
	fprintf(stream, "\""JSON_NDM_REFCNT_STRING"\":%d,", neighbour->stats.ndm_refcnt);
}

static const char* gen_neighbour_index(char* index, const struct tracked_data data)
{
	const struct neighbour_nohistory_data* const neighbour = (const struct neighbour_nohistory_data*)data.nohistory_data;

	snprintf(index,
		 NEIGHBOUR_INDEX_LENGTH,
		 "%X_%02X%02X%02X%02X%02X%02X",
		 neighbour->ndm_ifindex,
		 neighbour->mac[0],
		 neighbour->mac[1],
		 neighbour->mac[2],
		 neighbour->mac[3],
		 neighbour->mac[4],
		 neighbour->mac[5]);
	stpnprint_ip_dump(index + strlen(index), NEIGHBOUR_INDEX_LENGTH - strlen(index), neighbour->addr);

	return index;
}

static bool neighbour_changed(const struct tracked_data old, const struct tracked_data new)
{
	return memcmp(old.history_data, new.history_data, sizeof(struct neighbour_history_data)) != 0;
}

int add_ifaddr_entry(const int ifindex, const unsigned char family, const union ip addr, const unsigned char* const mac)
{
	char index[NEIGHBOUR_INDEX_LENGTH];

	struct data_tracker* const tracker = make_empty_data_tracker(neighbour_data_size);
	const struct tracked_data data = get_tracked_data(tracker);
	struct neighbour_nohistory_data* const neighbour = (struct neighbour_nohistory_data*)data.nohistory_data;
	struct neighbour_history_data* const current = (struct neighbour_history_data*)data.history_data;
	memset(current, 0x00, sizeof(struct neighbour_history_data));

	neighbour->ndm_ifindex = ifindex;
	current->ndm_state = NUD_REACHABLE;
	neighbour->ndm_family = family;

	memcpy(&(neighbour->addr), &addr, sizeof(union ip));
	memcpy(neighbour->mac, mac, 6);

	current->local = true;

	get_data_index(index, tracker, &gen_neighbour_index);
	if (save_data_tracker(&neighbour_table, &neighbour_mutex, index, tracker, &neighbour_changed)) {
		return MNL_CB_OK;
	} else {
		return MNL_CB_ERROR;
	}
}

int remove_ifaddr_entry(const int ifindex, const unsigned char family, const union ip addr, const unsigned char* mac)
{
	char index[NEIGHBOUR_INDEX_LENGTH];

	struct data_tracker* const tracker = make_empty_data_tracker(neighbour_data_size);
	const struct tracked_data data = get_tracked_data(tracker);
	struct neighbour_nohistory_data* const neighbour = (struct neighbour_nohistory_data*)data.nohistory_data;
	struct neighbour_history_data* const current = (struct neighbour_history_data*)data.history_data;
	memset(current, 0x00, sizeof(struct neighbour_history_data));

	neighbour->ndm_ifindex = ifindex;
	current->ndm_state = NUD_REACHABLE;
	neighbour->ndm_family = family;

	memcpy(&(neighbour->addr), &addr, sizeof(union ip));
	memcpy(neighbour->mac, mac, 6);

	current->local = true;

	set_deleted_data(tracker);

	get_data_index(index, tracker, &gen_neighbour_index);
	if (save_data_tracker(&neighbour_table, &neighbour_mutex, index, tracker, &neighbour_changed)) {
		return MNL_CB_OK;
	} else {
		return MNL_CB_ERROR;
	}
}

static bool get_neighbour_attr_cb(const struct nlattr* nl_attr, const struct tracked_data data)
{
	struct neighbour_nohistory_data* const neighbour = (struct neighbour_nohistory_data*)data.nohistory_data;
	/*struct neighbour_history_data* const current = (struct neighbour_history_data*)data.history_data;*/
	if (mnl_attr_type_valid(nl_attr, NDA_MAX) < 0) {
		syslog_syserror(LOG_ALERT, "Received invalid netlink attribute for neighbour");
		return false;
	}
	switch (mnl_attr_get_type(nl_attr)) {
	case NDA_DST:
		if (mnl_attr_copy_union_ip(&(neighbour->addr), nl_attr, neighbour->ndm_family) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid IPv4 address for neighbour");
			return false;
		}
		break;
	case NDA_LLADDR:
		if (mnl_attr_copy_binary(neighbour->mac, nl_attr, 6) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid MAC address for neighbour");
			return false;
		}
		break;
	case NDA_CACHEINFO:
		if (mnl_attr_copy_binary(&(neighbour->stats), nl_attr, sizeof(struct nda_cacheinfo)) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid cache info for neighbour");
			return false;
		}
		break;
	}
	return true;
}

static size_t get_neighbour_header_cb(const struct nlmsghdr* nl_header, const struct tracked_data data)
{
	struct neighbour_nohistory_data* const neighbour = (struct neighbour_nohistory_data*)data.nohistory_data;
	struct neighbour_history_data* const current = (struct neighbour_history_data*)data.history_data;

	const struct ndmsg* const ndm = (const struct ndmsg*)mnl_nlmsg_get_payload(nl_header);

	memset(current, 0x00, sizeof(struct neighbour_history_data));

	neighbour->ndm_family = ndm->ndm_family;
	neighbour->ndm_ifindex = ndm->ndm_ifindex;
	current->ndm_state = ndm->ndm_state;
	current->ndm_flags = ndm->ndm_flags;
	current->ndm_type = ndm->ndm_type;

	return sizeof(struct ndmsg);
}

int rtm_getneigh_cb(const struct nlmsghdr* nl_header, void* closure)
{
	return rtm_newneigh_cb(nl_header, closure);
}

int rtm_newneigh_cb(const struct nlmsghdr* nl_header, void* closure)
{
	char index[NEIGHBOUR_INDEX_LENGTH];
	struct data_tracker* const tracker = prepare_data_tracker(neighbour_data_size, nl_header, &get_neighbour_header_cb, &get_neighbour_attr_cb);
	get_data_index(index, tracker, &gen_neighbour_index);
	if (save_data_tracker(&neighbour_table, &neighbour_mutex, index, tracker, &neighbour_changed)) {
		return MNL_CB_OK;
	} else {
		return MNL_CB_ERROR;
	}
}

int rtm_delneigh_cb(const struct nlmsghdr* nl_header, void* closure)
{
	char index[NEIGHBOUR_INDEX_LENGTH];
	struct data_tracker* const tracker = prepare_data_tracker(neighbour_data_size, nl_header, &get_neighbour_header_cb, &get_neighbour_attr_cb);
	set_deleted_data(tracker);
	get_data_index(index, tracker, &gen_neighbour_index);
	if (save_data_tracker(&neighbour_table, &neighbour_mutex, index, tracker, &neighbour_changed)) {
		return MNL_CB_OK;
	} else {
		return MNL_CB_ERROR;
	}
}

void print_neighbours(FILE* stream)
{
	print_data_trackers(stream, &neighbour_table, &neighbour_mutex, &print_neighbour, &print_neighbour_diff, NEIGHBOUR_INDEX_LENGTH);
}

void clean_neighbour_table()
{
	clean_data_history(&neighbour_table, &neighbour_mutex, NEIGHBOUR_INDEX_LENGTH);
}

