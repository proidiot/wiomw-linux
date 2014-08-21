#include <config.h>
#include "nl_listener.h"

#include "configuration.h"
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <libmnl/libmnl.h>
#include <syslog.h>
#include <sysexits.h>
#include <stdlib.h>
#include "syslog_syserror.h"
#include "ifaddr.h"
#include "iface.h"
#include "neighbour.h"

static int nl_cb(const struct nlmsghdr* nlh, void* closure)
{
	switch (nlh->nlmsg_type) {
	case RTM_NEWLINK: return rtm_newlink_cb(nlh, closure);
	case RTM_DELLINK: return rtm_dellink_cb(nlh, closure);
	case RTM_GETLINK: return rtm_getlink_cb(nlh, closure);
	case RTM_NEWADDR: return rtm_newaddr_cb(nlh, closure);
	case RTM_DELADDR: return rtm_deladdr_cb(nlh, closure);
	case RTM_GETADDR: return rtm_getaddr_cb(nlh, closure);
	case RTM_NEWNEIGH: return rtm_newneigh_cb(nlh, closure);
	case RTM_DELNEIGH: return rtm_delneigh_cb(nlh, closure);
	case RTM_GETNEIGH: return rtm_getneigh_cb(nlh, closure);
	default: return MNL_CB_OK;
	}
}

void* nl_listener(void* closure)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct mnl_socket* nl_sock;
	ssize_t ret;

	if ((nl_sock = mnl_socket_open(NETLINK_ROUTE)) == NULL) {
		syslog_syserror(LOG_CRIT, "Unable to open netlink socket");
		exit(EX_OSERR);
	} else if (mnl_socket_bind(nl_sock, RTMGRP_LINK | RTMGRP_NEIGH | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR, MNL_SOCKET_AUTOPID) < 0) {
		syslog_syserror(LOG_CRIT, "Unable to bind netlink socket to port");
		exit(EX_OSERR);
	}

	while ((ret = mnl_socket_recvfrom(nl_sock, buf, MNL_SOCKET_BUFFER_SIZE)) > 0) {
		if (mnl_cb_run(buf, ret, 0, 0, &nl_cb, closure) < -1) {
			syslog_syserror(LOG_CRIT, "Error during parse of netlink data");
			exit(EX_SOFTWARE);
		}
	}

	if (ret < -1) {
		syslog_syserror(LOG_CRIT, "Unable to communicate with netlink socket");
		exit(EX_OSERR);
	}

	mnl_socket_close(nl_sock);

	return NULL;
}

