#include <config.h>
#include <stdio.h>
#include <sysexits.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "print_error.h"
#include "configuration.h"
#include "signal_handler.h"
#include "api.h"
#include "neighbours.h"

int main(int argc, char** argv)
{
	config_t config;
	/* TODO: Any additional declarations go here. */

	set_signal_handlers();

	config = get_configuration(argc, argv);


	wiomw_login(&config);
	fprintf(stderr, "DEBUG: %lX: got: %s\n", (unsigned long)time(NULL), config.str_session_id);

	while (!stop_signal_received()) {
		fprintf(stderr, "DEBUG: %lX: no stop signal yet\n", (unsigned long)time(NULL));
		/*wiomw_get_updates(&config);*/
		wiomw_send_updates(&config);
		alarm(GET_UPDATES_FREQUENCY);
		sleep_until_signalled();
	}




	/* TODO: Any remaining cleanup goes here. */
	return EX_OK;
}

