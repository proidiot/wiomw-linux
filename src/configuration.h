/* src/configuration.h.  Generated from configuration.h.in by configure.  */
#ifndef _WIOMW_CONFIGURATION_H_
#define _WIOMW_CONFIGURATION_H_

#include "sockaddr_helpers.h"
#include <stdbool.h>

typedef struct {
	char* username;
	char* passhash;
	char* agentkey;
	char* session_id;
	char* iface_blacklist_regex;
	char* login_url;
	char* sync_block_url;
	char* send_devices_url;
	network_list_t networks;
	bool ignore_blacklist_iface;
	bool show_unreachable_neighs;
	bool show_known_blacklist_iface_neighs;
	bool show_down_iface;
	bool show_secondary_iface_addr;
	bool blacklist_overrides_networks;
	bool autoscan;
} config_t;

config_t get_configuration(int argc, char** argv);

#endif
