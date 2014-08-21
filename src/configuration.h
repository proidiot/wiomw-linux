/**
 * Copyright 2013, 2014 Who Is On My WiFi.
 *
 * This file is part of Who Is On My WiFi Linux.
 *
 * Who Is On My WiFi Linux is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Who Is On My WiFi Linux is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Who Is On My WiFi Linux.  If not, see <http://www.gnu.org/licenses/>.
 *
 * More information about Who Is On My WiFi Linux can be found at
 * <http://www.whoisonmywifi.com/>.
 */

#ifndef _WIOMW_CONFIGURATION_H_
#define _WIOMW_CONFIGURATION_H_

#include "sockaddr_helpers.h"
#include <stdbool.h>
#include <sys/types.h>
#include <regex.h>

typedef struct _config_struct {
	time_t next_session_request;
	char* username;
	char* passhash;
	char* agentkey;
	char* session_id;
	char* iface_blacklist_regex;
	regex_t compiled_iface_blacklist_regex;
	char* capath;
	char* login_url;
	char* config_agent_url;
	char* config_subnet_url;
	char* sync_block_url;
	char* send_devices_url;
	char* dnsmasq_lease_file;
	network_list_t networks;
	bool ignore_blacklist_iface;
	bool show_unreachable_neighs;
	bool show_known_blacklist_iface_neighs;
	bool show_down_iface;
	bool show_secondary_iface_addr;
	bool blacklist_overrides_networks;
	bool autoscan;
	bool allow_blocking;
} * config_t;

config_t set_configuration(int argc, char** argv);

config_t get_configuration();

bool session_has_expired();

#endif
