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

#include <config.h>
#include <stdio.h>
#include <sysexits.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include "configuration.h"
#include "signal_handler.h"
#include "api.h"
#include "neighbours.h"

#define MINIMUM(a,b) (((a)>(b))?(b):(a))

#if CONFIG_OPTION_AUTHPRIV_LEVEL_SYSLOG == 1
#define WIOMW_SYSLOG_LEVEL LOG_AUTHPRIV
#else
#define WIOMW_SYSLOG_LEVEL LOG_DAEMON
#endif

int main(int argc, char** argv)
{
	config_t config;
	/* TODO: Any additional declarations go here. */
	
	openlog(CONFIG_OPTION_SYSLOG_IDENT, LOG_CONS | LOG_PERROR, WIOMW_SYSLOG_LEVEL);

	syslog(LOG_INFO, "Starting up...");

	set_signal_handlers();

	config = get_configuration(argc, argv);

	do {
		wiomw_login(&config);
		syslog(LOG_INFO, "Logged in successfully");

		if (send_config(&config) && !stop_signal_received() && !session_has_expired(config)) {
			syslog(LOG_INFO, "Version announced");
		} else {
			syslog(LOG_WARNING, "Skipping version announcement");
		}

		do {
			if (config.allow_blocking) {
				if (sync_block(&config) && !stop_signal_received() && !session_has_expired(config)) {
					syslog(LOG_INFO, "Device blocking updated");
				} else {
					syslog(LOG_WARNING, "Skipping block");
				}
			}
			syslog(LOG_INFO, "Collecting network device details...");
			if (send_subnet_and_devices(&config) && !stop_signal_received() && !session_has_expired(config)) {
				syslog(LOG_INFO, "Network device reports sent");
			} else {
				syslog(LOG_INFO, "Skipping scan");
			}
		} while (any_nap(CONFIG_OPTION_SYNC_BLOCK_FREQUENCY, config.next_session_request));

		if (session_has_expired(config)) {
			syslog(LOG_INFO, "Previous session has expired");
		}
	} while (!stop_signal_received());




	/* TODO: Any remaining cleanup goes here. */
	closelog();
	return EX_OK;
}

