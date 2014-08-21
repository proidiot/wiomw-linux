#ifndef _WIOMW_KHEADER_AUGMENT_H_
#define _WIOMW_KHEADER_AUGMENT_H_

#include <config.h>

#ifndef HAVE_STRUCT_NET_DEVICE_STATS_TX_PACKETS
struct net_device_stats {
	unsigned long rx_packets;
	unsigned long tx_packets;
	unsigned long rx_bytes;
	unsigned long tx_bytes;
	unsigned long rx_errors;
	unsigned long tx_errors;
	unsigned long rx_dropped;
	unsigned long tx_dropped;
	unsigned long multicast;
	unsigned long collisions;
	unsigned long rx_length_errors;
	unsigned long rx_over_errors;
	unsigned long rx_crc_errors;
	unsigned long rx_frame_errors;
	unsigned long rx_fifo_errors;
	unsigned long rx_missed_errors;
	unsigned long tx_aborted_errors;
	unsigned long tx_carrier_errors;
	unsigned long tx_fifo_errors;
	unsigned long tx_heartbeat_errors;
	unsigned long tx_window_errors;
	unsigned long rx_compressed;
	unsigned long tx_compressed;
};
#endif

#endif
