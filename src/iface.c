#include <config.h>
#include "iface.h"

struct _uniq_iface_struct {
	struct ifinfomsg ifinfo;
	unsigned char mac[6];
	unsigned char bmac[6];
	uint32_t mtu;
	int link;
	char* qdsp;
	char* name;
	bool blacklisted;
};

struct _iface_struct {
	time_t time;
	struct _uniq_iface_struct uiface;
	struct net_device_stats stats;
};

struct _uniq_ifaddr_struct {
	struct ifaddrmsg ifaddr;
	struct sockaddr_in6 addr;
	struct sockaddr_in6 local;
	struct sockaddr_in6 bcast;
	struct sockaddr_in6 acast;
	char* label;
};

struct _ifaddr_struct {
	time_t time;
	struct _uniq_ifaddr_struct uifaddr;
	struct ifa_cachinfo cacheinfo;
};

iface_t new_iface()
{
	/* TODO */
}

void delete_iface(iface_t* val)
{
	/* TODO */
}

iface_t get_iface_by_index(int index)
{
	/* TODO */
}

static int get_iface_attr_cb(const struct nlattr* nl_attr, void* closure)
{
	iface_t iface = (iface_t)closure;
	if (mnl_attr_type_valid(nl_attr, IFLA_MAX) < 0) {
		syslog_syserror(LOG_ALERT, "Received invalid netlink attribute type for local network device");
		return MNL_CB_ERROR;
	}
	switch (mnl_attr_get_type(nl_attr)) {
	case IFLA_ADDRESS:
		if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, 6) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid MAC address for local network device");
			return MNL_CB_ERROR;
		} else {
			memcpy(iface->uiface.mac, mnl_attr_get_payload(nl_attr), 6);
		}
		break;
	case IFLA_BROADCAST:
		if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, 6) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid broadcast MAC address for local network device");
			return MNL_CB_ERROR;
		} else {
			memcpy(iface->uiface.bmac, mnl_attr_get_payload(nl_attr), 6);
		}
		break;
	case IFLA_MTU:
		if (mnl_attr_validate(nl_attr, MNL_TYPE_U32) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid MTU for local network device");
			return MNL_CB_ERROR;
		} else {
			iface->uiface.mtu = mnl_attr_get_u32(nl_attr);
		}
		break;
	case IFLA_LINK:
		if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(int)) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid link type for local network device");
			return MNL_CB_ERROR;
		} else {
			memcpy(&iface->uiface.link, mnl_attr_get_payload(nl_attr), sizeof(int));
		}
		break;
	case IFLA_QDISC:
		if (mnl_attr_validate(nl_attr, MNL_TYPE_NUL_STRING) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid queue discipline for local network device");
			return MNL_CB_ERROR;
		} else if ((iface->uiface.qdisc = strdup(mnl_attr_get_str(nl_attr))) == NULL) {
			syslog_syserror(LOG_ALERT, "Unable to save queue discipline for local network device");
			return MNL_CB_ERROR;
		}
		break;
	case IFLA_IFNAME:
		if (mnl_attr_validate(nl_attr, MNL_TYPE_NUL_STRING) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid interface name for local network device");
			return MNL_CB_ERROR;
		} else if ((iface->uiface.name = strdup(mnl_attr_get_str(nl_attr))) == NULL) {
			syslog_syserror(LOG_ALERT, "Unable to save interface name for local network device");
			return MNL_CB_ERROR;
		}
		/* TODO check against regex */
		break;
	case IFLA_STATS:
		if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct net_device_stats)) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid interface statistics for local network device");
			return MNL_CB_ERROR;
		} else {
			memcpy(iface->stats, mnl_attr_get_payload(nl_attr), sizeof(struct net_device_stats));
		}
		break;
	}
	return MNL_CB_OK;
}

static iface_t get_iface(const struct nlmsghdr* nl_header)
{
	time_t now = time(NULL);
	iface_t iface = new_iface();
	iface->time = now;
	memcpy(iface->uiface.ifinfo, mnl_nlmsg_get_payload(nl_header), sizeof(struct ifinfomsg));
	if (mnl_attr_parse(nl_header, sizeof(struct ifinfomsg), &get_iface_attr_cb, (void*)iface) == MNL_CB_ERROR) {
		syslog_error(LOG_ALERT, "Unable to save local network interface data");
		delete_iface(&iface);
		return NULL;
	} else {
		return iface;
	}
}

static int get_ifaddr_attr_cb(const struct nlattr* nl_attr, void* closure)
{
	ifaddr_t ifaddr = (iface_t)closure;
	if (mnl_attr_type_valid(nl_attr, IFA_MAX) < 0) {
		syslog_syserror(LOG_ALERT, "Received invalid netlink attribute type for local network address");
		return MNL_CB_ERROR;
	}
	switch (mnl_attr_get_type(nl_attr)) {
	case IFA_ADDRESS:
		if (ifaddr->uifaddr.ifaddr.ifa_family == AF_INET) {
			if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct sockaddr_in)) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid IPv4 address for local network interface");
				return MNL_CB_ERROR;
			} else {
				memcpy(ifaddr->uifaddr.addr, mnl_attr_get_payload(nl_attr), sizeof(struct sockaddr_in));
			}
		} else if (ifaddr->uifaddr.ifaddr.ifa_family == AF_INET6) {
			if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct sockaddr_in6)) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid IPv6 address for local network interface");
				return MNL_CB_ERROR;
			} else {
				memcpy(ifaddr->uifaddr.addr, mnl_attr_get_payload(nl_attr), sizeof(struct sockaddr_in6));
			}
		} else {
			syslog_syserror(LOG_ALERT, "Received invalid IP address family for local network interface");
			return MNL_CB_ERROR;
		}
		break;
	case IFA_LOCAL:
		if (ifaddr->uifaddr.ifaddr.ifa_family == AF_INET) {
			if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct sockaddr_in)) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid IPv4 local address for local network interface");
				return MNL_CB_ERROR;
			} else {
				memcpy(ifaddr->uifaddr.local, mnl_attr_get_payload(nl_attr), sizeof(struct sockaddr_in));
			}
		} else if (ifaddr->uifaddr.ifaddr.ifa_family == AF_INET6) {
			if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct sockaddr_in6)) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid IPv6 local address for local network interface");
				return MNL_CB_ERROR;
			} else {
				memcpy(ifaddr->uifaddr.local, mnl_attr_get_payload(nl_attr), sizeof(struct sockaddr_in6));
			}
		} else {
			syslog_syserror(LOG_ALERT, "Received invalid IP local address family for local network interface");
			return MNL_CB_ERROR;
		}
		break;
	case IFA_LABEL:
		if (mnl_attr_validate(nl_attr, MNL_TYPE_NUL_STRING) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid label for local network address");
			return MNL_CB_ERROR;
		} else if ((ifaddr->uifaddr.label = strdup(mnl_attr_get_str(nl_attr))) == NULL) {
			syslog_syserror(LOG_ALERT, "Unable to save label for local network address");
			return MNL_CB_ERROR;
		}
		break;
	case IFA_BROADCAST:
		if (ifaddr->uifaddr.ifaddr.ifa_family == AF_INET) {
			if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct sockaddr_in)) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid IPv4 broadcast address for local network interface");
				return MNL_CB_ERROR;
			} else {
				memcpy(ifaddr->uifaddr.bcast, mnl_attr_get_payload(nl_attr), sizeof(struct sockaddr_in));
			}
		} else if (ifaddr->uifaddr.ifaddr.ifa_family == AF_INET6) {
			if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct sockaddr_in6)) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid IPv6 broadcast address for local network interface");
				return MNL_CB_ERROR;
			} else {
				memcpy(ifaddr->uifaddr.bcast, mnl_attr_get_payload(nl_attr), sizeof(struct sockaddr_in6));
			}
		} else {
			syslog_syserror(LOG_ALERT, "Received invalid IP broadcast address family for local network interface");
			return MNL_CB_ERROR;
		}
		break;
	case IFA_ANYCAST:
		if (ifaddr->uifaddr.ifaddr.ifa_family == AF_INET) {
			if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct sockaddr_in)) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid IPv4 anycast address for local network interface");
				return MNL_CB_ERROR;
			} else {
				memcpy(ifaddr->uifaddr.acast, mnl_attr_get_payload(nl_attr), sizeof(struct sockaddr_in));
			}
		} else if (ifaddr->uifaddr.ifaddr.ifa_family == AF_INET6) {
			if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct sockaddr_in6)) < 0) {
				syslog_syserror(LOG_ALERT, "Received invalid IPv6 anycast address for local network interface");
				return MNL_CB_ERROR;
			} else {
				memcpy(ifaddr->uifaddr.acast, mnl_attr_get_payload(nl_attr), sizeof(struct sockaddr_in6));
			}
		} else {
			syslog_syserror(LOG_ALERT, "Received invalid IP anycast address family for local network interface");
			return MNL_CB_ERROR;
		}
		break;
	case IFA_CACHEINFO:
		if (mnl_attr_validate2(nl_attr, MNL_TYPE_BINARY, sizeof(struct ifa_cacheinfo)) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid cache info for local network address");
			return MNL_CB_ERROR;
		} else {
			memcpy(ifaddr->stats, mnl_attr_get_payload(nl_attr), sizeof(struct ifa_cacheinfo));
		}
		break;
	}
	return MNL_CB_OK;
}

static ifaddr_t get_ifaddr(const struct nlmsghdr* nl_header)
{
	time_t now = time(NULL);
	ifaddr_t ifaddr = new_ifaddr();
	ifaddr->time = now;
	memcpy(ifaddr->uifaddr.ifaddr, mnl_nlmsg_get_payload(nl_header), sizeof(struct ifaddrmsg));
	if (mnl_attr_parse(nl_header, sizeof(struct ifinfomsg), &get_ifaddr_attr_cb, (void*)ifaddr) == MNL_CB_ERROR) {
		syslog_error(LOG_ALERT, "Unable to save local network address data");
		delete_ifaddr(&ifaddr);
		return NULL;
	} else {
		return ifaddr;
	}
}

int rtm_newlink_cb(const struct nlmsghdr* nl_header, void* closure)
{
	iface_t iface = get_iface(nl_header);
	/* TODO save iface*/
	return MNL_CB_OK;
}

int rtm_dellink_cb(const struct nlmsghdr* nl_header, void* closure)
{
	iface_t iface = get_iface(nl_header);
	/* TODO set iface as deleted */
	return MNL_CB_OK;
}

int rtm_newaddr_cb(const struct nlmsghdr* nl_header, void* closure)
{
	ifaddr_t ifaddr = get_ifaddr(nl_header);
	/* TODO save ifaddr */
	return MNL_CB_OK;
}

int rtm_deladdr_cb(const struct nlmsghdr* nl_header, void* closure)
{
	ifaddr_t ifaddr = get_ifaddr(nl_header);
	/* TODO set ifaddr as deleted */
	return MNL_CB_OK;
}


