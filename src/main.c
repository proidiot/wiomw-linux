#include <config.h>
#include <stdio.h>
#include <sysexits.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include "print_error.h"
#include "configuration.h"
#include "signal_handler.h"
#include "api.h"
#include "neighbours.h"

#define MINIMUM(a,b) (((a)>(b))?(b):(a))

int main(int argc, char** argv)
{
	time_t last_session_request = 0;
	config_t config;
	/* TODO: Any additional declarations go here. */

	set_signal_handlers();

	config = get_configuration(argc, argv);

	do {
		wiomw_login(&config);
		last_session_request = time(NULL);
		print_debug("Got: %s at %d", config.session_id, last_session_request);

		while (!stop_signal_received() && time(NULL) < (last_session_request + SESSION_LENGTH)) {
			time_t next_session_request_wait = 0;
			print_debug("no stop signal yet");
			if (config.allow_blocking) {
				sync_block(&config);
			}
			if (time(NULL) < (last_session_request + SESSION_LENGTH)) {
				send_devices(&config);
			}
			next_session_request_wait = (last_session_request + SESSION_LENGTH) - time(NULL);
			if (next_session_request_wait > 0) {
				alarm(MINIMUM(SYNC_BLOCK_FREQUENCY, next_session_request_wait));
				sleep_until_signalled();
			}
		}
	} while (!stop_signal_received());




	/* TODO: Any remaining cleanup goes here. */
	return EX_OK;
}

