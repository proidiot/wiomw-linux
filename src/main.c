/**
 * Copyright 2013 - 2015 Who Is On My WiFi.
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
#include <stdbool.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
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
	bool daemonized = false;
	pid_t process_id = 0;
	pid_t session_id = 0;
	config_t config;
	/* TODO: Any additional declarations go here. */
	
	if (daemonized) {
		if ((process_id = fork()) < 0) {
			fprintf(stderr, "Unable to fork daemon: %s\n", argv[0]);
			exit(EX_OSERR);
		} else if (process_id > 0) {
			/* daemonized! */
			exit(EXIT_SUCCESS);
		}
	
		umask(0);
	}

	openlog(CONFIG_OPTION_SYSLOG_IDENT, LOG_CONS | LOG_PERROR, WIOMW_SYSLOG_LEVEL);

	syslog(LOG_INFO, "Starting up...");

	if (daemonized) {
		if ((session_id = setsid()) < 0) {
			syslog(LOG_ERR, "Unable to create indpendent process group for daemon\n");
			exit(EX_OSERR);
		}
	
		if (chdir("/") < 0) {
			syslog(LOG_ERR, "Unable to change directory for daemon\n");
			exit(EX_OSERR);
		}
	}

	set_signal_handlers();

	config = get_configuration(argc, argv);

	if (daemonized) {
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);
	}

	do {
		wiomw_login(&config);
		syslog(LOG_INFO, "Logged in successfully");

		if (!stop_signal_received() && !session_has_expired(config) && send_config(&config)) {
			syslog(LOG_INFO, "Version announced");
		} else {
			syslog(LOG_WARNING, "Skipping version announcement");
		}

		do {
			if (config.allow_blocking) {
				if (!stop_signal_received() && !session_has_expired(config) && sync_block(&config)) {
					syslog(LOG_INFO, "Device blocking updated");
				} else {
					syslog(LOG_WARNING, "Skipping block");
				}
			}
			syslog(LOG_INFO, "Collecting network device details...");
			if (!stop_signal_received() && !session_has_expired(config) && send_subnet_and_devices(&config)) {
				syslog(LOG_INFO, "Network device reports sent");
			} else {
				syslog(LOG_INFO, "Skipping scan");
			}
		} while (!stop_signal_received() && any_nap(CONFIG_OPTION_SYNC_BLOCK_FREQUENCY, config.next_session_request) && !stop_signal_received() && !session_has_expired(config));

		if (!stop_signal_received() && session_has_expired(config)) {
			syslog(LOG_INFO, "Previous session has expired");
		}
	} while (!stop_signal_received());

	syslog(LOG_INFO, "Shutting down...");

	/* TODO: Any remaining cleanup goes here. */
	
	syslog(LOG_INFO, "Done");
	closelog();
	return EX_OK;
}

