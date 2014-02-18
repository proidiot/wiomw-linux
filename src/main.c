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
	time_t last_session_request = 0;
	config_t config;
	/* TODO: Any additional declarations go here. */
	
	openlog(CONFIG_OPTION_SYSLOG_IDENT, LOG_CONS | LOG_PERROR, WIOMW_SYSLOG_LEVEL);

	syslog(LOG_INFO, "Starting up...");

	set_signal_handlers();

	config = get_configuration(argc, argv);

	do {
		wiomw_login(&config);
		syslog(LOG_INFO, "Logged in successfully");

		last_session_request = time(NULL);
		send_config(&config);
		syslog(LOG_INFO, "Version announced");

		while (!stop_signal_received() && time(NULL) < (last_session_request + CONFIG_OPTION_SESSION_LENGTH)) {
			time_t next_session_request_wait = 0;
			if (config.allow_blocking) {
				sync_block(&config);
				syslog(LOG_INFO, "Device blocking updated");
			}
			if (time(NULL) < (last_session_request + CONFIG_OPTION_SESSION_LENGTH)) {
				send_subnet_and_devices(&config);
				syslog(LOG_INFO, "Network device reports sent");
			}
			next_session_request_wait = (last_session_request + CONFIG_OPTION_SESSION_LENGTH) - time(NULL);
			if (next_session_request_wait > 0) {
				alarm(MINIMUM(CONFIG_OPTION_SYNC_BLOCK_FREQUENCY, next_session_request_wait));
				sleep_until_signalled();
			}
		}
		syslog(LOG_INFO, "Previous session has expired");
	} while (!stop_signal_received());




	/* TODO: Any remaining cleanup goes here. */
	closelog();
	return EX_OK;
}

