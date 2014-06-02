#include <config.h>
#include "neighbour.h"
#include <stdbool.h>
#include <string.h>

struct _uniq_neighbour_struct {
	struct ndmsg nd;
	struct sockaddr_in6 ip;
	unsigned char mac[6];
};

struct _neighbour_struct {
	time_t time;
	bool local;
	struct _uniq_neighbour_struct uneighbour;
	struct nda_cacheinfo stats;
};

neighbour_t new_neighbour()
{
	neighbour_t neighbour = (neighbour_t)malloc(sizeof(struct _neighbour_struct));
	memset(neighbour, NULL, sizeof(struct _neighbour_struct));
	return neighbour;
}

void destroy_neighbour(neighbour_t* neighbour)
{
	free(*neighbour);
	*neighbour = NULL;
}

void add_ifaddr_entry(int index, unsigned char family, struct sockaddr* ip, unsigned char* mac)
{
	time_t now = time(NULL);
	neighbour_t neighbour = new_neighbour();
	neighbour->time = now;
	neighbour->uneighbour.nd.ndm_ifindex = index;
	neighbour->uneighbour.nd.ndm_state = NUD_REACHABLE;
	neighbour->uneighbour.nd.ndm_family = ip->sa_family;
	if (ip->sa_family == AF_INET) {
		memcpy(neighbour->uneighbour.ip, ip, sizeof(struct sockaddr_in));
	} else if (ip->sa_family == AF_INET6) {
		memcpy(neighbour->uneighbour.ip, ip, sizeof(struct sockaddr_in6));
	}
	memcpy(neighbour->uneighbour.mac, mac, 6);
	neighbour->local = true;
	/* TODO: save neighbour */
}

void remove_ifaddr_entry(int index, unsigned char family, struct sockaddr* ip, unsigned char* mac)
{
	time_t now = time(NULL);
	neighbour_t neighbour = new_neighbour();
	neighbour->time = now;
	neighbour->uneighbour.nd.ndm_ifindex = index;
	neighbour->uneighbour.nd.ndm_family = ip->sa_family;
	if (ip->sa_family == AF_INET) {
		memcpy(neighbour->uneighbour.ip, ip, sizeof(struct sockaddr_in));
	} else if (ip->sa_family == AF_INET6) {
		memcpy(neighbour->uneighbour.ip, ip, sizeof(struct sockaddr_in6));
	}
	memcpy(neighbour->uneighbour.mac, mac, 6);
	neighbour->local = true;
	/* TODO: save neighbour */
}

static int get_neighbour_attr_cb(const struct nlattr* nl_attr, void* closure)
{
	neighbour_t neighbour = (neighbour_t)closure;
	if (mnl_attr_type_valid(nl_attr, NDA_MAX) < 0) {
		syslog_syserror(LOG_ALERT, "Received invalid netlink attribute for neighbour");
		return MNL_CB_ERROR;
	}
	switch (mnl_attr_get_type(nl_attr)) {
	case NDA_DST:
		if (neighbour->uneighbour.nd.ndm_family == AF_INET) {
			if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct sockaddr_in)) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid IPv4 address for neighbour");
				return MNL_CB_ERROR;
			} else {
				memcpy(neighbour->uneighbour.ip, mnl_attr_get_payload(nl_attr), sizeof(struct sockaddr_in));
			}
		} else if (neighbour->uneighbour.nd.ndm_family == AF_INET6) {
			if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct sockaddr_in6)) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid IPv6 address for neighbour");
				return MNL_CB_ERROR;
			} else {
				memcpy(neighbour->uneighbour.ip, mnl_attr_get_payload(nl_attr), sizeof(struct sockaddr_in6));
			}
		} else {
			syslog_syserror(LOG_ALERT, "Received invalid IP address family for neighbour");
			return MNL_CB_ERROR;
		}
		break;
	case NDA_LLADDR:
		if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, 6) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid MAC address for neighbour");
			return MNL_CB_ERROR;
		} else {
			memcpy(neighbour->uneighbour.mac, mnl_attr_get_payload(nl_attr), 6);
		}
		break;
	case NDA_CACHEINFO:
		if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct nds_cacheinfo)) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid cache info for neighbour");
			return MNL_CB_ERROR;
		} else {
			memcpy(neighbour->stats, mnl_attr_get_payload(nl_attr), sizeof(struct nda_cacheinfo));
		}
		break;
	}
	return MNL_CB_OK;
}

neighbour_t get_neighbour(const struct nlmsghdr* nl_header)
{
	time_t now = time(NULL);
	neighbour_t neighbour = new_neighbour();
	neighbour->time = now;
	memcpy(neighbour->uneighbour.nd, mnl_nlmsg_get_payload(nl_header), sizeof(struct ndmsg));
	if (mnl_attr_parse(nl_header, sizeof(struct ndmsg), &get_neighbour_attr_cb, (void*)neighbour) == MNL_CB_ERROR) {
		syslog_syserror(LOG_ALERT, "Unable to save neighbour data");
		destroy_neighbour(&neighbour);
		return NULL;
	} else {
		return neighbour;
	}
}

int rtm_newneigh_cb(const struct nlmsghdr* nl_header, void* closure)
{
	neighbour_t neighbour = get_neighbour(nl_header);
	/* TODO: save neighbour */
	return MNL_CB_OK;
}

int rtm_delneigh_cb(const struct nlmsghdr* nl_header, void* closure)
{
	neighbour_t neighbour = get_neighbour(nl_header);
	/* TODO: set neighbour as deleted */
	return MNL_CB_OK;
}

#endif
