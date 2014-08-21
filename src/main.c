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
#include <pthread.h>
#include <sysexits.h>
#include "configuration.h"
#include "signal_handler.h"
#include "syslog_syserror.h"
#include "api.h"
#include "neighbours.h"
#include "nl_listener.h"

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
	pthread_attr_t attr;
	pthread_t thread;
	
	openlog(CONFIG_OPTION_SYSLOG_IDENT, LOG_CONS | LOG_PERROR, WIOMW_SYSLOG_LEVEL);

	syslog(LOG_INFO, "Starting up...");

	set_signal_handlers();

	config = set_configuration(argc, argv);

	if (pthread_attr_init(&attr) != 0) {
		syslog_syserror(LOG_CRIT, "Unable to initialize thread metadata");
		exit(EX_OSERR);
	}

	if (pthread_create(&thread, &attr, &nl_listener, NULL) != 0) {
		syslog_syserror(LOG_CRIT, "Unable to start network device listener");
		exit(EX_OSERR);
	}

	do {
		wiomw_login(&config);
		syslog(LOG_INFO, "Logged in successfully");

		if (send_config(&config) && !stop_signal_received() && !session_has_expired(config)) {
			syslog(LOG_INFO, "Version announced");
		} else {
			syslog(LOG_WARNING, "Skipping version announcement");
		}

		do {
			if (config->allow_blocking) {
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
		} while (any_nap(CONFIG_OPTION_SYNC_BLOCK_FREQUENCY, config->next_session_request));

		if (session_has_expired(config)) {
			syslog(LOG_INFO, "Previous session has expired");
		}
	} while (!stop_signal_received());

	if (pthread_cancel(thread) != 0) {
		syslog_syserror(LOG_CRIT, "Unable to stop network device listener");
	}

	if (pthread_attr_destroy(&attr) != 0) {
		syslog_syserror(LOG_CRIT, "Unable to clean up thread metadata");
	}

	/* TODO: Any remaining cleanup goes here. */
	closelog();
	return EX_OK;
}

