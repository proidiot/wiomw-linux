#include <config.h>
#include "iface.h"
#include <stdio.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <asm/types.h>
#include <stdbool.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <string.h>
#include <stdlib.h>
#include <libmnl/libmnl.h>
#include <syslog.h>
#include "configuration.h"
#include "syslog_syserror.h"
#include "kheader_augment.h"
#include "data_tracker.h"
#include "mnl_helpers.h"

#define IFACE_INDEX_LENGTH ((sizeof(int) * 2) + 1)

#define JSON_IFI_FAMILY_STRING "family"
#define JSON_IFI_TYPE_STRING "type"
#define JSON_IFF_UP_STRING "up"
#define JSON_IFF_BROADCAST_STRING "broadcast"
#define JSON_IFF_DEBUG_STRING "debug"
#define JSON_IFF_LOOPBACK_STRING "loopback"
#define JSON_IFF_POINTTOPOINT_STRING "point2point"
#define JSON_IFF_NOTRAILERS_STRING "notrailers"
#define JSON_IFF_RUNNING_STRING "running"
#define JSON_IFF_PROMISC_STRING "promisc"
#define JSON_IFF_NOARP_STRING "noarp"
#define JSON_IFF_ALLMULTI_STRING "allmulti"
#define JSON_IFF_MASTER_STRING "master"
#define JSON_IFF_SLAVE_STRING "slave"
#define JSON_IFF_MULTICAST_STRING "multicast"
#define JSON_IFF_PORTSEL_STRING "portsel"
#define JSON_IFF_AUTOMEDIA_STRING "automedia"
#define JSON_IFF_DYNAMIC_STRING "dynamic"
#define JSON_IFF_LOWER_UP_STRING "lowerup"
#define JSON_IFF_DORMANT_STRING "dormant"
#define JSON_IFF_ECHO_STRING "echo"
#define JSON_IFF_VOLATILE_STRING "volatile"
#define JSON_IFLA_ADDRESS_STRING "mac"
#define JSON_IFLA_BROADCAST_STRING "bcast_mac"
#define JSON_IFLA_LINK_STRING "real_iface"
#define JSON_IFLA_MTU_STRING "mtu"
#define JSON_IFLA_QDISC_STRING "qdsp"
#define JSON_IFLA_IFNAME_STRING "name"

#define JSON_IFLA_STATS_RX_PACKETS_STRING "rx_packets"
#define JSON_IFLA_STATS_TX_PACKETS_STRING "tx_packets"
#define JSON_IFLA_STATS_RX_BYTES_STRING "rx_bytes"
#define JSON_IFLA_STATS_TX_BYTES_STRING "tx_bytes"
#define JSON_IFLA_STATS_RX_ERRORS_STRING "rx_errors"
#define JSON_IFLA_STATS_TX_ERRORS_STRING "tx_errors"
#define JSON_IFLA_STATS_RX_DROPPED_STRING "rx_dropped"
#define JSON_IFLA_STATS_TX_DROPPED_STRING "tx_dropped"
#define JSON_IFLA_STATS_MULTICAST_STRING "multicast"
#define JSON_IFLA_STATS_COLLISIONS_STRING "collisions"
#define JSON_IFLA_STATS_RX_LENGTH_ERRORS_STRING "rx_length_errors"
#define JSON_IFLA_STATS_RX_OVER_ERRORS_STRING "rx_over_errors"
#define JSON_IFLA_STATS_RX_CRC_ERRORS_STRING "rx_crc_errors"
#define JSON_IFLA_STATS_RX_FRAME_ERRORS_STRING "rx_frame_errors"
#define JSON_IFLA_STATS_RX_FIFO_ERRORS_STRING "rx_fifo_errors"
#define JSON_IFLA_STATS_RX_MISSED_ERRORS_STRING "rx_missed_errors"
#define JSON_IFLA_STATS_TX_ABORTED_ERRORS_STRING "tx_aborted_errors"
#define JSON_IFLA_STATS_TX_CARRIER_ERRORS_STRING "tx_carrier_errors"
#define JSON_IFLA_STATS_TX_FIFO_ERRORS_STRING "tx_fifo_errors"
#define JSON_IFLA_STATS_TX_HEARTBEAT_ERRORS_STRING "tx_heartbeat_errors"
#define JSON_IFLA_STATS_TX_WINDOW_ERRORS_STRING "tx_window_errors"
#define JSON_IFLA_STATS_RX_COMPRESSED_STRING "rx_compressed"
#define JSON_IFLA_STATS_TX_COMPRESSED_STRING "tx_compressed"

#define JSON_BLACKLISTED_STRING "blacklisted"

struct iface_history_data {
	unsigned char ifi_family;
	unsigned short ifi_type;
	unsigned int ifi_flags;
	unsigned char mac[6];
	unsigned char bmac[6];
	uint32_t mtu;
	int link;
	char qdsp[IFNAMSIZ];
	char name[IFNAMSIZ];
	bool blacklisted;
};

struct iface_nohistory_data {
	struct net_device_stats stats;
	int ifi_index;
};

static const struct tracked_data_size iface_data_size =
	{
		.nohistory_data_len = sizeof(struct iface_nohistory_data),
		.history_data_len = sizeof(struct iface_history_data)
	};

static Pvoid_t iface_table = (Pvoid_t)NULL;
/*static pthread_mutex_t iface_mutex = PTHREAD_MUTEX_ERRORCHECK_INITIALIZER_NP;*/
static pthread_mutex_t iface_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char* const get_af_family(const unsigned char family)
{
	switch (family) {
	case AF_UNSPEC:
		return "AF_UNSPEC";
		break;
#ifdef AF_LOCAL
	case AF_LOCAL:
		return "AF_LOCAL";
		break;
#endif
/*
#ifdef AF_UNIX
	case AF_UNIX:
		return "AF_UNIX";
		break;
#endif
#ifdef AF_FILE
	case AF_FILE:
		return "AF_FILE";
		break;
#endif
*/
#ifdef AF_INET
	case AF_INET:
		return "AF_INET";
		break;
#endif
#ifdef AF_AX25
	case AF_AX25:
		return "AF_AX25";
		break;
#endif
#ifdef AF_IPX
	case AF_IPX:
		return "AF_IPX";
		break;
#endif
#ifdef AF_APPLETALK
	case AF_APPLETALK:
		return "AF_APPLETALK";
		break;
#endif
#ifdef AF_NETROM
	case AF_NETROM:
		return "AF_NETROM";
		break;
#endif
#ifdef AF_BRIDGE
	case AF_BRIDGE:
		return "AF_BRIDGE";
		break;
#endif
#ifdef AF_ATMPVC
	case AF_ATMPVC:
		return "AF_ATMPVC";
		break;
#endif
#ifdef AF_X25
	case AF_X25:
		return "AF_X25";
		break;
#endif
#ifdef AF_INET6
	case AF_INET6:
		return "AF_INET6";
		break;
#endif
#ifdef AF_ROSE
	case AF_ROSE:
		return "AF_ROSE";
		break;
#endif
#ifdef AF_DECnet
	case AF_DECnet:
		return "AF_DECnet";
		break;
#endif
#ifdef AF_NETBEUI
	case AF_NETBEUI:
		return "AF_NETBEUI";
		break;
#endif
#ifdef AF_SECURITY
	case AF_SECURITY:
		return "AF_SECURITY";
		break;
#endif
#ifdef AF_KEY
	case AF_KEY:
		return "AF_KEY";
		break;
#endif
#ifdef AF_NETLINK
	case AF_NETLINK:
		return "AF_NETLINK";
		break;
#endif
/*
#ifdef AF_ROUTE
	case AF_ROUTE:
		return "AF_ROUTE";
		break;
#endif
*/
#ifdef AF_PACKET
	case AF_PACKET:
		return "AF_PACKET";
		break;
#endif
#ifdef AF_ASH
	case AF_ASH:
		return "AF_ASH";
		break;
#endif
#ifdef AF_ECONET
	case AF_ECONET:
		return "AF_ECONET";
		break;
#endif
#ifdef AF_ATMSVC
	case AF_ATMSVC:
		return "AF_ATMSVC";
		break;
#endif
#ifdef AF_RDS
	case AF_RDS:
		return "AF_RDS";
		break;
#endif
#ifdef AF_SNA
	case AF_SNA:
		return "AF_SNA";
		break;
#endif
#ifdef AF_IRDA
	case AF_IRDA:
		return "AF_IRDA";
		break;
#endif
#ifdef AF_PPPOX
	case AF_PPPOX:
		return "AF_PPPOX";
		break;
#endif
#ifdef AF_WANPIPE
	case AF_WANPIPE:
		return "AF_WANPIPE";
		break;
#endif
#ifdef AF_LLC
	case AF_LLC:
		return "AF_LLC";
		break;
#endif
#ifdef AF_CAN
	case AF_CAN:
		return "AF_CAN";
		break;
#endif
#ifdef AF_TIPC
	case AF_TIPC:
		return "AF_TIPC";
		break;
#endif
#ifdef AF_BLUETOOTH
	case AF_BLUETOOTH:
		return "AF_BLUETOOTH";
		break;
#endif
#ifdef AF_IUCV
	case AF_IUCV:
		return "AF_IUCV";
		break;
#endif
#ifdef AF_RXRPC
	case AF_RXRPC:
		return "AF_RXRPC";
		break;
#endif
#ifdef AF_ISDN
	case AF_ISDN:
		return "AF_ISDN";
		break;
#endif
#ifdef AF_PHONET
	case AF_PHONET:
		return "AF_PHONET";
		break;
#endif
#ifdef AF_IEEE802154
	case AF_IEEE802154:
		return "AF_IEEE802154";
		break;
#endif
#ifdef AF_CAIF
	case AF_CAIF:
		return "AF_CAIF";
		break;
#endif
#ifdef AF_ALG
	case AF_ALG:
		return "AF_ALG";
		break;
#endif
#ifdef AF_NFC
	case AF_NFC:
		return "AF_NFC";
		break;
#endif
	case AF_MAX:
		return "AF_MAX";
		break;
	default:
		return NULL;
		break;
	};
}

static const char* const get_arp_hw_type(const unsigned short type)
{
	switch (type) {
#ifdef ARPHRD_NETROM
	case ARPHRD_NETROM:
		return "ARPHRD_NETROM";
		break;
#endif
#ifdef ARPHRD_ETHER
	case ARPHRD_ETHER:
		return "ARPHRD_ETHER";
		break;
#endif
#ifdef ARPHRD_EETHER
	case ARPHRD_EETHER:
		return "ARPHRD_EETHER";
		break;
#endif
#ifdef ARPHRD_AX25
	case ARPHRD_AX25:
		return "ARPHRD_AX25";
		break;
#endif
#ifdef ARPHRD_PRONET
	case ARPHRD_PRONET:
		return "ARPHRD_PRONET";
		break;
#endif
#ifdef ARPHRD_CHAOS
	case ARPHRD_CHAOS:
		return "ARPHRD_CHAOS";
		break;
#endif
#ifdef ARPHRD_IEEE802
	case ARPHRD_IEEE802:
		return "ARPHRD_IEEE802";
		break;
#endif
#ifdef ARPHRD_ARCNET
	case ARPHRD_ARCNET:
		return "ARPHRD_ARCNET";
		break;
#endif
#ifdef ARPHRD_APPLETLK
	case ARPHRD_APPLETLK:
		return "ARPHRD_APPLETLK";
		break;
#endif
#ifdef ARPHRD_DLCI
	case ARPHRD_DLCI:
		return "ARPHRD_DLCI";
		break;
#endif
#ifdef ARPHRD_ATM
	case ARPHRD_ATM:
		return "ARPHRD_ATM";
		break;
#endif
#ifdef ARPHRD_METRICOM
	case ARPHRD_METRICOM:
		return "ARPHRD_METRICOM";
		break;
#endif
#ifdef ARPHRD_IEEE1394
	case ARPHRD_IEEE1394:
		return "ARPHRD_IEEE1394";
		break;
#endif
#ifdef ARPHRD_EUI64
	case ARPHRD_EUI64:
		return "ARPHRD_EUI64";
		break;
#endif
#ifdef ARPHRD_INFINIBAND
	case ARPHRD_INFINIBAND:
		return "ARPHRD_INFINIBAND";
		break;
#endif
#ifdef ARPHRD_SLIP
	case ARPHRD_SLIP:
		return "ARPHRD_SLIP";
		break;
#endif
#ifdef ARPHRD_CSLIP
	case ARPHRD_CSLIP:
		return "ARPHRD_CSLIP";
		break;
#endif
#ifdef ARPHRD_SLIP6
	case ARPHRD_SLIP6:
		return "ARPHRD_SLIP6";
		break;
#endif
#ifdef ARPHRD_CSLIP6
	case ARPHRD_CSLIP6:
		return "ARPHRD_CSLIP6";
		break;
#endif
#ifdef ARPHRD_RSRVD
	case ARPHRD_RSRVD:
		return "ARPHRD_RSRVD";
		break;
#endif
#ifdef ARPHRD_ADAPT
	case ARPHRD_ADAPT:
		return "ARPHRD_ADAPT";
		break;
#endif
#ifdef ARPHRD_ROSE
	case ARPHRD_ROSE:
		return "ARPHRD_ROSE";
		break;
#endif
#ifdef ARPHRD_X25
	case ARPHRD_X25:
		return "ARPHRD_X25";
		break;
#endif
#ifdef ARPHRD_HWX25
	case ARPHRD_HWX25:
		return "ARPHRD_HWX25";
		break;
#endif
#ifdef ARPHRD_CAN
	case ARPHRD_CAN:
		return "ARPHRD_CAN";
		break;
#endif
#ifdef ARPHRD_PPP
	case ARPHRD_PPP:
		return "ARPHRD_PPP";
		break;
#endif
#ifdef ARPHRD_CISCO
	case ARPHRD_CISCO:
		return "ARPHRD_CISCO";
		break;
#endif
/*
#ifdef ARPHRD_HDLC
	case ARPHRD_HDLC:
		return "ARPHRD_HDLC";
		break;
#endif
*/
#ifdef ARPHRD_LAPB
	case ARPHRD_LAPB:
		return "ARPHRD_LAPB";
		break;
#endif
#ifdef ARPHRD_DDCMP
	case ARPHRD_DDCMP:
		return "ARPHRD_DDCMP";
		break;
#endif
#ifdef ARPHRD_RAWHDLC
	case ARPHRD_RAWHDLC:
		return "ARPHRD_RAWHDLC";
		break;
#endif
#ifdef ARPHRD_TUNNEL
	case ARPHRD_TUNNEL:
		return "ARPHRD_TUNNEL";
		break;
#endif
#ifdef ARPHRD_TUNNEL6
	case ARPHRD_TUNNEL6:
		return "ARPHRD_TUNNEL6";
		break;
#endif
#ifdef ARPHRD_FRAD
	case ARPHRD_FRAD:
		return "ARPHRD_FRAD";
		break;
#endif
#ifdef ARPHRD_SKIP
	case ARPHRD_SKIP:
		return "ARPHRD_SKIP";
		break;
#endif
#ifdef ARPHRD_LOOPBACK
	case ARPHRD_LOOPBACK:
		return "ARPHRD_LOOPBACK";
		break;
#endif
#ifdef ARPHRD_LOCALTLK
	case ARPHRD_LOCALTLK:
		return "ARPHRD_LOCALTLK";
		break;
#endif
#ifdef ARPHRD_FDDI
	case ARPHRD_FDDI:
		return "ARPHRD_FDDI";
		break;
#endif
#ifdef ARPHRD_BIF
	case ARPHRD_BIF:
		return "ARPHRD_BIF";
		break;
#endif
#ifdef ARPHRD_SIT
	case ARPHRD_SIT:
		return "ARPHRD_SIT";
		break;
#endif
#ifdef ARPHRD_IPDDP
	case ARPHRD_IPDDP:
		return "ARPHRD_IPDDP";
		break;
#endif
#ifdef ARPHRD_IPGRE
	case ARPHRD_IPGRE:
		return "ARPHRD_IPGRE";
		break;
#endif
#ifdef ARPHRD_PIMREG
	case ARPHRD_PIMREG:
		return "ARPHRD_PIMREG";
		break;
#endif
#ifdef ARPHRD_HIPPI
	case ARPHRD_HIPPI:
		return "ARPHRD_HIPPI";
		break;
#endif
#ifdef ARPHRD_ASH
	case ARPHRD_ASH:
		return "ARPHRD_ASH";
		break;
#endif
#ifdef ARPHRD_ECONET
	case ARPHRD_ECONET:
		return "ARPHRD_ECONET";
		break;
#endif
#ifdef ARPHRD_IRDA
	case ARPHRD_IRDA:
		return "ARPHRD_IRDA";
		break;
#endif
#ifdef ARPHRD_FCPP
	case ARPHRD_FCPP:
		return "ARPHRD_FCPP";
		break;
#endif
#ifdef ARPHRD_FCAL
	case ARPHRD_FCAL:
		return "ARPHRD_FCAL";
		break;
#endif
#ifdef ARPHRD_FCPL
	case ARPHRD_FCPL:
		return "ARPHRD_FCPL";
		break;
#endif
#ifdef ARPHRD_FCFABRIC
	case ARPHRD_FCFABRIC:
		return "ARPHRD_FCFABRIC";
		break;
#endif
#ifdef ARPHRD_IEEE802_TR
	case ARPHRD_IEEE802_TR:
		return "ARPHRD_IEEE802_TR";
		break;
#endif
#ifdef ARPHRD_IEEE80211
	case ARPHRD_IEEE80211:
		return "ARPHRD_IEEE80211";
		break;
#endif
#ifdef ARPHRD_IEEE80211_PRISM
	case ARPHRD_IEEE80211_PRISM:
		return "ARPHRD_IEEE80211_PRISM";
		break;
#endif
#ifdef ARPHRD_IEEE80211_RADIOTAP
	case ARPHRD_IEEE80211_RADIOTAP:
		return "ARPHRD_IEEE80211_RADIOTAP";
		break;
#endif
#ifdef ARPHRD_IEEE802154
	case ARPHRD_IEEE802154:
		return "ARPHRD_IEEE802154";
		break;
#endif
#ifdef ARPHRD_PHONET
	case ARPHRD_PHONET:
		return "ARPHRD_PHONET";
		break;
#endif
#ifdef ARPHRD_PHONET_PIPE
	case ARPHRD_PHONET_PIPE:
		return "ARPHRD_PHONET_PIPE";
		break;
#endif
#ifdef ARPHRD_CAIF
	case ARPHRD_CAIF:
		return "ARPHRD_CAIF";
		break;
#endif
#ifdef ARPHRD_VOID
	case ARPHRD_VOID:
		return "ARPHRD_VOID";
		break;
#endif
#ifdef ARPHRD_NONE
	case ARPHRD_NONE:
		return "ARPHRD_NONE";
		break;
#endif
	default:
		return NULL;
		break;
	};
}

static void print_ifi_flag_diff(FILE* stream, const unsigned int target, const unsigned int reference)
{
	const unsigned int tflags = target ^ reference;
	if (tflags == 0) {
		return;
	}
	if (tflags & IFF_UP) {
		fprintf(stream, "\""JSON_IFF_UP_STRING"\":%d,", (target & IFF_UP) != 0);
	}
	if (tflags & IFF_BROADCAST) {
		fprintf(stream, "\""JSON_IFF_BROADCAST_STRING"\":%d,", (target & IFF_BROADCAST) != 0);
	}
	if (tflags & IFF_DEBUG) {
		fprintf(stream, "\""JSON_IFF_DEBUG_STRING"\":%d,", (target & IFF_DEBUG) != 0);
	}
	if (tflags & IFF_LOOPBACK) {
		fprintf(stream, "\""JSON_IFF_LOOPBACK_STRING"\":%d,", (target & IFF_LOOPBACK) != 0);
	}
	if (tflags & IFF_POINTOPOINT) {
		fprintf(stream, "\""JSON_IFF_POINTTOPOINT_STRING"\":%d,", (target & IFF_POINTOPOINT) != 0);
	}
	if (tflags & IFF_NOTRAILERS) {
		fprintf(stream, "\""JSON_IFF_NOTRAILERS_STRING"\":%d,", (target & IFF_NOTRAILERS) != 0);
	}
	if (tflags & IFF_RUNNING) {
		fprintf(stream, "\""JSON_IFF_RUNNING_STRING"\":%d,", (target & IFF_RUNNING) != 0);
	}
	if (tflags & IFF_NOARP) {
		fprintf(stream, "\""JSON_IFF_NOARP_STRING"\":%d,", (target & IFF_NOARP) != 0);
	}
	if (tflags & IFF_PROMISC) {
		fprintf(stream, "\""JSON_IFF_PROMISC_STRING"\":%d,", (target & IFF_PROMISC) != 0);
	}
	if (tflags & IFF_ALLMULTI) {
		fprintf(stream, "\""JSON_IFF_ALLMULTI_STRING"\":%d,", (target & IFF_ALLMULTI) != 0);
	}
	if (tflags & IFF_MASTER) {
		fprintf(stream, "\""JSON_IFF_MASTER_STRING"\":%d,", (target & IFF_MASTER) != 0);
	}
	if (tflags & IFF_SLAVE) {
		fprintf(stream, "\""JSON_IFF_SLAVE_STRING"\":%d,", (target & IFF_SLAVE) != 0);
	}
	if (tflags & IFF_MULTICAST) {
		fprintf(stream, "\""JSON_IFF_MULTICAST_STRING"\":%d,", (target & IFF_MULTICAST) != 0);
	}
	if (tflags & IFF_PORTSEL) {
		fprintf(stream, "\""JSON_IFF_PORTSEL_STRING"\":%d,", (target & IFF_PORTSEL) != 0);
	}
	if (tflags & IFF_AUTOMEDIA) {
		fprintf(stream, "\""JSON_IFF_AUTOMEDIA_STRING"\":%d,", (target & IFF_AUTOMEDIA) != 0);
	}
	if (tflags & IFF_DYNAMIC) {
		fprintf(stream, "\""JSON_IFF_DYNAMIC_STRING"\":%d,", (target & IFF_DYNAMIC) != 0);
	}
	if (tflags & IFF_LOWER_UP) {
		fprintf(stream, "\""JSON_IFF_LOWER_UP_STRING"\":%d,", (target & IFF_LOWER_UP) != 0);
	}
	if (tflags & IFF_DORMANT) {
		fprintf(stream, "\""JSON_IFF_DORMANT_STRING"\":%d,", (target & IFF_DORMANT) != 0);
	}
	if (tflags & IFF_ECHO) {
		fprintf(stream, "\""JSON_IFF_ECHO_STRING"\":%d,", (target & IFF_ECHO) != 0);
	}
	if (tflags & IFF_VOLATILE) {
		fprintf(stream, "\""JSON_IFF_VOLATILE_STRING"\":%d,", (target & IFF_VOLATILE) != 0);
	}
}

static void print_iface_diff(FILE* stream, const struct tracked_data old_data, const struct tracked_data new_data)
{
	/*const struct iface_nohistory_data* const old_nohist = (const struct iface_nohistory_data*)old_data.nohistory_data;*/
	const struct iface_history_data* const old = (const struct iface_history_data*)old_data.history_data;
	const struct iface_history_data* const new = (const struct iface_history_data*)new_data.history_data;
	if (old->ifi_family != new->ifi_family) {
		if (get_af_family(old->ifi_family) != NULL) {
			fprintf(stream, "\""JSON_IFI_FAMILY_STRING"\":\"%s\",", get_af_family(old->ifi_family));
		} else {
			fprintf(stream, "\""JSON_IFI_FAMILY_STRING"\":\"Unknown (%X)\",", old->ifi_family);
		}
	}
	if (old->ifi_type != new->ifi_type) {
		if (get_arp_hw_type(old->ifi_type) != NULL) {
			fprintf(stream, "\""JSON_IFI_TYPE_STRING"\":\"%s\",", get_arp_hw_type(old->ifi_type));
		} else {
			fprintf(stream, "\""JSON_IFI_TYPE_STRING"\":\"Unknown (%X)\",", old->ifi_type);
		}
	}
	print_ifi_flag_diff(stream, old->ifi_flags, new->ifi_flags);
	if (memcmp(old->mac, new->mac, 6) != 0) {
		fprintf(stream,
			"\""JSON_IFLA_ADDRESS_STRING"\":\"%02X:%02X:%02X:%02X:%02X:%02X\",",
			old->mac[0],
			old->mac[1],
			old->mac[2],
			old->mac[3],
			old->mac[4],
			old->mac[5]);
	}
	if (memcmp(old->bmac, new->bmac, 6) != 0) {
		fprintf(stream,
			"\""JSON_IFLA_BROADCAST_STRING"\":\"%02X:%02X:%02X:%02X:%02X:%02X\",",
			old->bmac[0],
			old->bmac[1],
			old->bmac[2],
			old->bmac[3],
			old->bmac[4],
			old->bmac[5]);
	}
	if (old->mtu != new->mtu) {
		fprintf(stream, "\""JSON_IFLA_MTU_STRING"\":%d,", old->mtu);
	}
	if (old->link != new->link) {
		char link_name[IFNAMSIZ];
		get_iface_name(link_name, old->link);
		fprintf(stream, "\""JSON_IFLA_LINK_STRING"\":\"%s\",", link_name);
	}
	if (strncmp(old->qdsp, new->qdsp, IFNAMSIZ) != 0) {
		fprintf(stream, "\""JSON_IFLA_QDISC_STRING"\":\"%s\",", old->qdsp);
	}
	if (strncmp(old->name, new->name, IFNAMSIZ) != 0) {
		fprintf(stream, "\""JSON_IFLA_IFNAME_STRING"\":\"%s\",", old->name);
	}
	if (old->blacklisted != new->blacklisted) {
		fprintf(stream, "\""JSON_BLACKLISTED_STRING"\":%d,", old->blacklisted);
	}
}

static void print_iface(FILE* stream, const struct tracked_data data)
{
	const struct iface_nohistory_data* const iface = (const struct iface_nohistory_data*)data.nohistory_data;
	const struct iface_history_data* const current = (const struct iface_history_data*)data.history_data;
	char link_name[IFNAMSIZ];
	fprintf(stream, "\""JSON_IFI_FAMILY_STRING"\":\"%s\",", get_af_family(current->ifi_family));
	fprintf(stream, "\""JSON_IFI_TYPE_STRING"\":\"%s\",", get_arp_hw_type(current->ifi_type));
	print_ifi_flag_diff(stream, current->ifi_flags, 0);
	fprintf(stream,
		"\""JSON_IFLA_ADDRESS_STRING"\":\"%02X:%02X:%02X:%02X:%02X:%02X\",",
		current->mac[0],
		current->mac[1],
		current->mac[2],
		current->mac[3],
		current->mac[4],
		current->mac[5]);
	fprintf(stream,
		"\""JSON_IFLA_BROADCAST_STRING"\":\"%02X:%02X:%02X:%02X:%02X:%02X\",",
		current->bmac[0],
		current->bmac[1],
		current->bmac[2],
		current->bmac[3],
		current->bmac[4],
		current->bmac[5]);
	fprintf(stream, "\""JSON_IFLA_MTU_STRING"\":%d,", current->mtu);
	get_iface_name(link_name, current->link);
	fprintf(stream, "\""JSON_IFLA_LINK_STRING"\":\"%s\",", link_name);
	fprintf(stream, "\""JSON_IFLA_QDISC_STRING"\":\"%s\",", current->qdsp);
	fprintf(stream, "\""JSON_IFLA_IFNAME_STRING"\":\"%s\",", current->name);
	fprintf(stream, "\""JSON_BLACKLISTED_STRING"\":%d,", current->blacklisted);

	fprintf(stream, "\""JSON_IFLA_STATS_RX_PACKETS_STRING"\":%lu,", iface->stats.rx_packets);
	fprintf(stream, "\""JSON_IFLA_STATS_TX_PACKETS_STRING"\":%lu,", iface->stats.tx_packets);
	fprintf(stream, "\""JSON_IFLA_STATS_RX_BYTES_STRING"\":%lu,", iface->stats.rx_bytes);
	fprintf(stream, "\""JSON_IFLA_STATS_TX_BYTES_STRING"\":%lu,", iface->stats.tx_bytes);
	fprintf(stream, "\""JSON_IFLA_STATS_RX_ERRORS_STRING"\":%lu,", iface->stats.rx_errors);
	fprintf(stream, "\""JSON_IFLA_STATS_TX_ERRORS_STRING"\":%lu,", iface->stats.tx_errors);
	fprintf(stream, "\""JSON_IFLA_STATS_RX_DROPPED_STRING"\":%lu,", iface->stats.rx_dropped);
	fprintf(stream, "\""JSON_IFLA_STATS_TX_DROPPED_STRING"\":%lu,", iface->stats.tx_dropped);
	fprintf(stream, "\""JSON_IFLA_STATS_MULTICAST_STRING"\":%lu,", iface->stats.multicast);
	fprintf(stream, "\""JSON_IFLA_STATS_COLLISIONS_STRING"\":%lu,", iface->stats.collisions);
	fprintf(stream, "\""JSON_IFLA_STATS_RX_LENGTH_ERRORS_STRING"\":%lu,", iface->stats.rx_length_errors);
	fprintf(stream, "\""JSON_IFLA_STATS_RX_OVER_ERRORS_STRING"\":%lu,", iface->stats.rx_over_errors);
	fprintf(stream, "\""JSON_IFLA_STATS_RX_CRC_ERRORS_STRING"\":%lu,", iface->stats.rx_crc_errors);
	fprintf(stream, "\""JSON_IFLA_STATS_RX_FRAME_ERRORS_STRING"\":%lu,", iface->stats.rx_frame_errors);
	fprintf(stream, "\""JSON_IFLA_STATS_RX_FIFO_ERRORS_STRING"\":%lu,", iface->stats.rx_fifo_errors);
	fprintf(stream, "\""JSON_IFLA_STATS_RX_MISSED_ERRORS_STRING"\":%lu,", iface->stats.rx_missed_errors);
	fprintf(stream, "\""JSON_IFLA_STATS_TX_ABORTED_ERRORS_STRING"\":%lu,", iface->stats.tx_aborted_errors);
	fprintf(stream, "\""JSON_IFLA_STATS_TX_CARRIER_ERRORS_STRING"\":%lu,", iface->stats.tx_carrier_errors);
	fprintf(stream, "\""JSON_IFLA_STATS_TX_FIFO_ERRORS_STRING"\":%lu,", iface->stats.tx_fifo_errors);
	fprintf(stream, "\""JSON_IFLA_STATS_TX_HEARTBEAT_ERRORS_STRING"\":%lu,", iface->stats.tx_heartbeat_errors);
	fprintf(stream, "\""JSON_IFLA_STATS_TX_WINDOW_ERRORS_STRING"\":%lu,", iface->stats.tx_window_errors);
	fprintf(stream, "\""JSON_IFLA_STATS_RX_COMPRESSED_STRING"\":%lu,", iface->stats.rx_compressed);
	fprintf(stream, "\""JSON_IFLA_STATS_TX_COMPRESSED_STRING"\":%lu,", iface->stats.tx_compressed);
}

static const char* gen_iface_index(char* index, const int ifindex)
{
	snprintf(index, IFACE_INDEX_LENGTH, "%X", ifindex);
	index[IFACE_INDEX_LENGTH - 1] = '\0';
	return index;
}

static const char* get_iface_index(char* index, const struct tracked_data data)
{
	const struct iface_nohistory_data* const iface = (const struct iface_nohistory_data*)data.nohistory_data;

	return gen_iface_index(index, iface->ifi_index);
}

static bool iface_changed(const struct tracked_data old_data, const struct tracked_data new_data)
{
	return memcmp(old_data.history_data, new_data.history_data, sizeof(struct iface_history_data)) != 0;
}

static bool get_iface_attr_cb(const struct nlattr* nl_attr, const struct tracked_data data)
{
	struct iface_nohistory_data* const iface = (struct iface_nohistory_data*)data.nohistory_data;
	struct iface_history_data* const current = (struct iface_history_data*)data.history_data;
	if (mnl_attr_type_valid(nl_attr, IFLA_MAX) < 0) {
		syslog_syserror(LOG_ALERT, "Received invalid netlink attribute type for local network device");
		return false;
	}
	switch (mnl_attr_get_type(nl_attr)) {
	case IFLA_ADDRESS:
		if (mnl_attr_copy_binary(current->mac, nl_attr, 6) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid MAC address for local network device");
			return false;
		}
		break;
	case IFLA_BROADCAST:
		if (mnl_attr_copy_binary(current->bmac, nl_attr, 6) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid broadcast MAC address for local network device");
			return false;
		}
		break;
	case IFLA_MTU:
		if (mnl_attr_validate(nl_attr, MNL_TYPE_U32) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid MTU for local network device");
			return false;
		} else {
			current->mtu = mnl_attr_get_u32(nl_attr);
		}
		break;
	case IFLA_LINK:
		if (mnl_attr_copy_binary(&(current->link), nl_attr, sizeof(int)) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid link type for local network device");
			return false;
		}
		break;
	case IFLA_QDISC:
		if (mnl_attr_validate(nl_attr, MNL_TYPE_NUL_STRING) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid queue discipline for local network device");
			return false;
		} else {
			strncpy(current->qdsp, mnl_attr_get_str(nl_attr), IFNAMSIZ);
		}
		break;
	case IFLA_IFNAME:
		if (mnl_attr_validate(nl_attr, MNL_TYPE_NUL_STRING) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid interface name for local network device");
			return false;
		} else {
			int errcode;
			config_t config = get_configuration();
			strncpy(current->name, mnl_attr_get_str(nl_attr), IFNAMSIZ);
			errcode = regexec(&(config->compiled_iface_blacklist_regex), current->name, 0, NULL, 0);
			if (errcode == 0) {
				current->blacklisted = true;
			} else if (errcode == REG_NOMATCH) {
				current->blacklisted = false;
			} else {
				syslog_syserror(LOG_CRIT, "Unable to evaluate the interface blacklist regex");
				return false;
			}
		}
		break;
	case IFLA_STATS:
		if (mnl_attr_copy_binary(&(iface->stats), nl_attr, sizeof(struct net_device_stats)) < 0) {
			syslog_syserror(LOG_ALERT, "Received invalid interface statistics for local network device");
			return false;
		}
		break;
	}
	return true;
}

static size_t get_iface_header_cb(const struct nlmsghdr* nl_header, const struct tracked_data data)
{
	struct iface_nohistory_data* const iface = (struct iface_nohistory_data*)data.nohistory_data;
	struct iface_history_data* const current = (struct iface_history_data*)data.history_data;

	struct ifinfomsg* ifinfo = mnl_nlmsg_get_payload(nl_header);

	memset(current, 0x00, sizeof(struct iface_history_data));

	current->ifi_family = ifinfo->ifi_family;
	current->ifi_type = ifinfo->ifi_type;
	iface->ifi_index = ifinfo->ifi_index;
	current->ifi_flags = ifinfo->ifi_flags;

	return sizeof(struct ifinfomsg);
}

static void save_iface_name(void* closure, const struct tracked_data data)
{
	char* name = (char*)closure;
	const struct iface_history_data* const current = (const struct iface_history_data*)data.history_data;
	strncpy(name, current->name, IFNAMSIZ);
}

void get_iface_name(char* name, const int ifindex)
{
	char index[IFACE_INDEX_LENGTH];
	gen_iface_index(index, ifindex);

	process_data_from_table(&save_iface_name, name, &iface_table, &iface_mutex, index);
}

static void save_iface_blacklisted(void* closure, const struct tracked_data data)
{
	bool* blacklisted = (bool*)closure;
	const struct iface_history_data* const current = (const struct iface_history_data*)data.history_data;
	*blacklisted = current->blacklisted;
}

void get_iface_blacklisted(bool* blacklisted, const int ifindex)
{
	char index[IFACE_INDEX_LENGTH];
	gen_iface_index(index, ifindex);

	process_data_from_table(&save_iface_blacklisted, &blacklisted, &iface_table, &iface_mutex, index);
}

static void save_iface_mac(void* closure, const struct tracked_data data)
{
	const struct iface_history_data* const current = (const struct iface_history_data*)data.history_data;
	memcpy(closure, current->mac, 6);
}

void get_iface_mac(unsigned char* mac, const int ifindex)
{
	char index[IFACE_INDEX_LENGTH];
	gen_iface_index(index, ifindex);

	process_data_from_table(&save_iface_mac, mac, &iface_table, &iface_mutex, index);
}

static void print_iface_wrapper(void* closure, const struct tracked_data data)
{
	print_iface((FILE*)closure, data);
}

void print_iface_by_index(FILE* stream, int ifindex)
{
	char index[IFACE_INDEX_LENGTH];
	gen_iface_index(index, ifindex);

	process_data_from_table(&print_iface_wrapper, stream, &iface_table, &iface_mutex, index);
}

int rtm_getlink_cb(const struct nlmsghdr* nl_header, void* closure)
{
	return rtm_newlink_cb(nl_header, closure);
}

int rtm_newlink_cb(const struct nlmsghdr* nl_header, void* closure)
{
	char index[IFACE_INDEX_LENGTH];
	struct data_tracker* const tracker = prepare_data_tracker(iface_data_size, nl_header, &get_iface_header_cb, &get_iface_attr_cb);
	get_data_index(index, tracker, &get_iface_index);
	if (save_data_tracker(&iface_table, &iface_mutex, index, tracker, &iface_changed)) {
		return MNL_CB_OK;
	} else {
		return MNL_CB_ERROR;
	}
}

int rtm_dellink_cb(const struct nlmsghdr* nl_header, void* closure)
{
	char index[IFACE_INDEX_LENGTH];
	struct data_tracker* const tracker = prepare_data_tracker(iface_data_size, nl_header, &get_iface_header_cb, &get_iface_attr_cb);
	set_deleted_data(tracker);
	get_data_index(index, tracker, &get_iface_index);
	if (save_data_tracker(&iface_table, &iface_mutex, index, tracker, &iface_changed)) {
		return MNL_CB_OK;
	} else {
		return MNL_CB_ERROR;
	}
}

void print_ifaces(FILE* stream)
{
	print_data_trackers(stream, &iface_table, &iface_mutex, &print_iface, &print_iface_diff, IFACE_INDEX_LENGTH);
}

void clean_iface_table()
{
	clean_data_history(&iface_table, &iface_mutex, IFACE_INDEX_LENGTH);
}

