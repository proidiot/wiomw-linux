#include <config.h>
#include "ifaddr.h"
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <arpa/inet.h>
#include <linux/if_addr.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libmnl/libmnl.h>
#include <syslog.h>
#include <time.h>
#include <linux/if.h>
#include <linux/if_addr.h>
#include <pthread.h>
#include <Judy.h>
#include "configuration.h"
#include "syslog_syserror.h"
#include "ip.h"
#include "data_tracker.h"
#include "iface.h"
#include "string_helpers.h"
#include "mnl_helpers.h"
#include "neighbour.h"

#define IFADDR_INDEX_LENGTH ((sizeof(int) * 2) + 1 + STPNPRINT_IP_DUMP_LEN + 1)

#define JSON_IFA_FAMILY_STRING "family"
#define JSON_IFA_PREFIXLEN_STRING "prefixlen"
#define JSON_IFA_FLAG_SECONDARY_STRING "secondary"
#define JSON_IFA_FLAG_PERMANENT_STRING "permanent"
#define JSON_IFA_SCOPE_STRING "scope"
#define JSON_IFA_ADDRESS_IPV4_STRING "ipaddress"
#define JSON_IFA_ADDRESS_IPV6_STRING "ip6"
#define JSON_IFA_LOCAL_IPV4_STRING "local"
#define JSON_IFA_LOCAL_IPV6_STRING "local6"
#define JSON_IFA_LABEL_STRING "label"
#define JSON_IFA_BROADCAST_IPV4_STRING "bcast"
#define JSON_IFA_BROADCAST_IPV6_STRING "bcast6"
#define JSON_IFA_ANYCAST_IPV4_STRING "acast"
#define JSON_IFA_ANYCAST_IPV6_STRING "acast6"
#define JSON_IFA_CACHEINFO_PREFERED_STRING "preferred"
#define JSON_IFA_CACHEINFO_VALID_STRING "valid"
#define JSON_IFA_CACHEINFO_CSTAMP_STRING "cstamp"
#define JSON_IFA_CACHEINFO_TSTAMP_STRING "tstamp"
#define JSON_BLACKLISTED_STRING "blacklisted"
#define JSON_PARENT_STRING "parent"

#define JSON_ADDR_STRING(af, which) (af == AF_INET)?"\""JSON_##which##_IPV4_STRING"\":\"%s\",":"\""JSON_##which##_IPV6_STRING"\":\"%s\","

/* In order to use memcmp for ifaddr_changed,
 * any possibly unclean structs must be copied one item at a time,
 * and this struct itself must be memset. */
struct ifaddr_history_data {
	union ip local;
	union ip bcast;
	union ip acast;
	bool blacklisted;
	unsigned char ifa_prefixlen;
	unsigned char ifa_flags;
	unsigned char ifa_scope;
	char label[IFNAMSIZ];
};

struct ifaddr_nohistory_data {
	union ip addr;
	struct ifa_cacheinfo cacheinfo;
	int ifa_index;
	unsigned char ifa_family;
};

static const struct tracked_data_size ifaddr_data_size =
	{
		nohistory_data_len: sizeof(struct ifaddr_nohistory_data),
		history_data_len: sizeof(struct ifaddr_history_data)
	};

static Pvoid_t ifaddr_table = (Pvoid_t)NULL;
/*static pthread_mutex_t ifaddr_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;*/
static pthread_mutex_t ifaddr_mutex = PTHREAD_MUTEX_INITIALIZER;

static void print_ifaddr_ifa_flags(FILE* stream, const unsigned char target, const unsigned char reference)
{
	const unsigned char tflags = target ^ reference;

	if (tflags & IFA_F_PERMANENT) {
		fprintf(stream, "\""JSON_IFA_FLAG_PERMANENT_STRING"\":%d,", (target & IFA_F_PERMANENT) == 0);
	}
	if (tflags & IFA_F_SECONDARY) {
		fprintf(stream, "\""JSON_IFA_FLAG_SECONDARY_STRING"\":%d,", (target & IFA_F_SECONDARY) == 0);
	}
}

static void print_ifaddr_diff(FILE* stream, const struct tracked_data old_data, const struct tracked_data new_data)
{
	const struct ifaddr_history_data* const old = (const struct ifaddr_history_data*)old_data.history_data;
	const struct ifaddr_nohistory_data* const old_nohist = (const struct ifaddr_nohistory_data*)old_data.nohistory_data;
	const struct ifaddr_history_data* const new = (const struct ifaddr_history_data*)new_data.history_data;

	char temp[BUFSIZ];

	if (old->ifa_prefixlen != new->ifa_prefixlen) {
		fprintf(stream, "\""JSON_IFA_PREFIXLEN_STRING"\":%d,", old->ifa_prefixlen);
	}
	print_ifaddr_ifa_flags(stream, old->ifa_flags, new->ifa_flags);
	if (old->ifa_scope != new->ifa_scope) {
		fprintf(stream, "\""JSON_IFA_SCOPE_STRING"\":%d,", old->ifa_scope);
	}
	if (memcmp(&(old->local), &(new->local), sizeof(union ip)) != 0) {
		snprint_ip(temp, BUFSIZ, old_nohist->ifa_family, old->local);
		fprintf(stream, JSON_ADDR_STRING(old_nohist->ifa_family, IFA_LOCAL), temp);
	}
	if (memcmp(&(old->bcast), &(new->bcast), sizeof(union ip)) != 0) {
		snprint_ip(temp, BUFSIZ, old_nohist->ifa_family, old->bcast);
		fprintf(stream, JSON_ADDR_STRING(old_nohist->ifa_family, IFA_BROADCAST), temp);
	}
	if (memcmp(&(old->acast), &(new->acast), sizeof(union ip)) != 0) {
		snprint_ip(temp, BUFSIZ, old_nohist->ifa_family, old->acast);
		fprintf(stream, JSON_ADDR_STRING(old_nohist->ifa_family, IFA_ANYCAST), temp);
	}
	if (memcmp(old->label, new->label, IFNAMSIZ) != 0) {
		fprintf(stream, "\""JSON_IFA_LABEL_STRING"\":\"%s\",", old->label);
	}
	if (old->blacklisted != new->blacklisted) {
		fprintf(stream, "\""JSON_BLACKLISTED_STRING"\":%d,", old->blacklisted);
	}
}

static void print_ifaddr(FILE* stream, const struct tracked_data data)
{
	const struct ifaddr_nohistory_data* const ifaddr = (const struct ifaddr_nohistory_data*)data.nohistory_data;
	const struct ifaddr_history_data* const current = (const struct ifaddr_history_data*)data.history_data;
	char temp[BUFSIZ];

	fprintf(stream, "\""JSON_IFA_FAMILY_STRING"\":\"%s\",", (ifaddr->ifa_family)? "AF_INET" : "AF_INET6");
	fprintf(stream, "\""JSON_IFA_PREFIXLEN_STRING"\":%d,", current->ifa_prefixlen);
	print_ifaddr_ifa_flags(stream, current->ifa_flags, 0);
	fprintf(stream, "\""JSON_IFA_SCOPE_STRING"\":%d,", current->ifa_scope);
	snprint_ip(temp, BUFSIZ, ifaddr->ifa_family, ifaddr->addr);
	fprintf(stream, JSON_ADDR_STRING(ifaddr->ifa_family, IFA_ADDRESS), temp);
	snprint_ip(temp, BUFSIZ, ifaddr->ifa_family, current->local);
	fprintf(stream, JSON_ADDR_STRING(ifaddr->ifa_family, IFA_LOCAL), temp);
	snprint_ip(temp, BUFSIZ, ifaddr->ifa_family, current->bcast);
	fprintf(stream, JSON_ADDR_STRING(ifaddr->ifa_family, IFA_BROADCAST), temp);
	snprint_ip(temp, BUFSIZ, ifaddr->ifa_family, current->acast);
	fprintf(stream, JSON_ADDR_STRING(ifaddr->ifa_family, IFA_ANYCAST), temp);
	fprintf(stream, "\""JSON_IFA_LABEL_STRING"\":\"%s\",", current->label);
	fprintf(stream, "\""JSON_BLACKLISTED_STRING"\":%d,", current->blacklisted);

	fprintf(stream, "\""JSON_IFA_CACHEINFO_PREFERED_STRING"\":%d,", ifaddr->cacheinfo.ifa_prefered);
	fprintf(stream, "\""JSON_IFA_CACHEINFO_VALID_STRING"\":%d,", ifaddr->cacheinfo.ifa_valid);
	fprintf(stream, "\""JSON_IFA_CACHEINFO_CSTAMP_STRING"\":%d,", ifaddr->cacheinfo.cstamp);
	fprintf(stream, "\""JSON_IFA_CACHEINFO_TSTAMP_STRING"\":%d,", ifaddr->cacheinfo.tstamp);

	fprintf(stream, "\""JSON_PARENT_STRING"\":");
	print_iface_by_index(stream, ifaddr->ifa_index);
	fprintf(stream, ",");
}

static const char* ifaddr_index(char* const index, const struct tracked_data data)
{
	const struct ifaddr_nohistory_data* const ifaddr = (const struct ifaddr_nohistory_data*)data.nohistory_data;

	char* tindex = index;

	const int ifindex = ifaddr->ifa_index;
	const union ip addr = ifaddr->addr;

	tindex = stpnprintf(tindex, IFADDR_INDEX_LENGTH, "%X_", ifindex);
	tindex = stpnprint_ip_dump(tindex, IFADDR_INDEX_LENGTH + index - tindex, addr);
	index[IFADDR_INDEX_LENGTH - 1] = '\0';

	return index;
}

static bool ifaddr_changed(const struct tracked_data old_data, const struct tracked_data new_data)
{
	return memcmp(old_data.history_data, new_data.history_data, ifaddr_data_size.history_data_len) != 0;
}

static bool ifaddr_attr_cb(const struct nlattr* nl_attr, const struct tracked_data data)
{
	struct ifaddr_nohistory_data* const ifaddr = (struct ifaddr_nohistory_data*)data.nohistory_data;
	struct ifaddr_history_data* const current = (struct ifaddr_history_data*)data.history_data;

	if (mnl_attr_type_valid(nl_attr, IFA_MAX) < 0) {
		syslog_syserror(LOG_ALERT, "Received invalid netlink attribute type for local network address");
		return false;
	}

	switch (mnl_attr_get_type(nl_attr)) {
	case IFA_ADDRESS:
		if (mnl_attr_copy_union_ip(&(ifaddr->addr), nl_attr, ifaddr->ifa_family) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid IP address for local network interface");
			return false;
		}
		break;
	case IFA_LOCAL:
		if (mnl_attr_copy_union_ip(&(current->local), nl_attr, ifaddr->ifa_family) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid local IP address for local network interface");
			return false;
		}
		break;
	case IFA_LABEL:
		if (mnl_attr_validate(nl_attr, MNL_TYPE_NUL_STRING) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid label for local network address");
			return false;
		} else {
			const char* tstr = mnl_attr_get_str(nl_attr);
			if (strnlen(tstr, IFNAMSIZ) != 0) {
				strncpy(current->label, tstr, IFNAMSIZ);
				int errcode;
				config_t config = get_configuration();
				errcode = regexec(&(config->compiled_iface_blacklist_regex), current->label, 0, NULL, 0);
				if (errcode == 0) {
					current->blacklisted = true;
				} else if (errcode == REG_NOMATCH) {
					get_iface_blacklisted(&(current->blacklisted), ifaddr->ifa_index);
				} else {
					syslog_syserror(LOG_CRIT, "Unable to evaluate the interface blacklist regex");
					return false;
				}
			} else {
				char name[IFNAMSIZ];
				get_iface_name(name, ifaddr->ifa_index);
				strcpy(current->label, name);
				get_iface_blacklisted(&(current->blacklisted), ifaddr->ifa_index);
			}
		}
		break;
	case IFA_BROADCAST:
		if (mnl_attr_copy_union_ip(&(current->bcast), nl_attr, ifaddr->ifa_family) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid broadcast IP address for local network interface");
			return false;
		}
		break;
	case IFA_ANYCAST:
		if (mnl_attr_copy_binary(&(current->acast.ip4), nl_attr, ifaddr->ifa_family) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid anycast IP address for local network interface");
			return false;
		}
		break;
	case IFA_CACHEINFO:
		if (mnl_attr_copy_binary(&(ifaddr->cacheinfo), nl_attr, sizeof(struct ifa_cacheinfo)) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid cache info for local network address");
			return false;
		}
		break;
	}

	return true;
}

static size_t ifaddr_header_cb(const struct nlmsghdr* nl_header, const struct tracked_data data)
{
	struct ifaddr_nohistory_data* const ifaddr = (struct ifaddr_nohistory_data*)data.nohistory_data;
	struct ifaddr_history_data* const current = (struct ifaddr_history_data*)data.history_data;
	struct ifaddrmsg* original_ifaddr = mnl_nlmsg_get_payload(nl_header);

	memset(current, 0x00, ifaddr_data_size.history_data_len);

	ifaddr->ifa_family = original_ifaddr->ifa_family;
	current->ifa_prefixlen = original_ifaddr->ifa_prefixlen;
	current->ifa_flags = original_ifaddr->ifa_flags & (IFA_F_PERMANENT | IFA_F_SECONDARY);
	current->ifa_scope = original_ifaddr->ifa_scope;
	ifaddr->ifa_index = original_ifaddr->ifa_index;

	return sizeof(struct ifaddrmsg);
}

int rtm_getaddr_cb(const struct nlmsghdr* nl_header, void* closure)
{
	return rtm_newaddr_cb(nl_header, closure);
}

int rtm_newaddr_cb(const struct nlmsghdr* nl_header, void* closure)
{
	char index[IFADDR_INDEX_LENGTH];
	struct data_tracker* const tracker = prepare_data_tracker(ifaddr_data_size, nl_header, &ifaddr_header_cb, &ifaddr_attr_cb);
	get_data_index(index, tracker, &ifaddr_index);
	if (save_data_tracker(&ifaddr_table, &ifaddr_mutex, index, tracker, &ifaddr_changed)) {
		const struct tracked_data data = get_tracked_data(tracker);
		const struct ifaddr_nohistory_data* const ifaddr = (const struct ifaddr_nohistory_data*)data.nohistory_data;
		/*const struct ifaddr_history_data* const current = (const struct ifaddr_history_data*)data.history_data;*/
		unsigned char mac[6];
		get_iface_mac(mac, ifaddr->ifa_index);
		return add_ifaddr_entry(ifaddr->ifa_index, ifaddr->ifa_family, ifaddr->addr, mac);
	} else {
		return MNL_CB_ERROR;
	}
}

int rtm_deladdr_cb(const struct nlmsghdr* nl_header, void* closure)
{
	char index[IFADDR_INDEX_LENGTH];
	struct data_tracker* const tracker = prepare_data_tracker(ifaddr_data_size, nl_header, &ifaddr_header_cb, &ifaddr_attr_cb);
	set_deleted_data(tracker);
	get_data_index(index, tracker, &ifaddr_index);
	if (save_data_tracker(&ifaddr_table, &ifaddr_mutex, index, tracker, &ifaddr_changed)) {
		const struct tracked_data data = get_tracked_data(tracker);
		const struct ifaddr_nohistory_data* const ifaddr = (const struct ifaddr_nohistory_data*)data.nohistory_data;
		/*const struct ifaddr_history_data* const current = (const struct ifaddr_history_data*)data.history_data;*/
		unsigned char mac[6];
		get_iface_mac(mac, ifaddr->ifa_index);
		return remove_ifaddr_entry(ifaddr->ifa_index, ifaddr->ifa_family, ifaddr->addr, mac);
	} else {
		return MNL_CB_ERROR;
	}
}

void print_ifaddrs(FILE* stream)
{
	print_data_trackers(stream, &ifaddr_table, &ifaddr_mutex, &print_ifaddr, &print_ifaddr_diff, IFADDR_INDEX_LENGTH);
}

void clean_ifaddr_table()
{
	clean_data_history(&ifaddr_table, &ifaddr_mutex, IFADDR_INDEX_LENGTH);
	clean_iface_table();
}

