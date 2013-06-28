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

#define MAX_SEND_UPDATES_SIZE 131072

int main()
{
	char str_temp[MAX_SEND_UPDATES_SIZE];
	FILE* fd = fmemopen(str_temp, MAX_SEND_UPDATES_SIZE, "w");
	print_neighbours(fd);
	fclose(fd);

	printf("%s\n", str_temp);

/*
	config_t config;
	char* str_session_id;
*/	/* TODO: Any additional declarations go here. */
/*
	set_signal_handlers();

	config = get_configuration(CONFIG_FILE_LOCATION);


	str_session_id = wiomw_login(LOGIN_API_URL, config);


	fprintf(stderr, "DEBUG: %lX: logged in\n", (unsigned long)time(NULL));

	while (!stop_signal_received()) {
		fprintf(stderr, "DEBUG: %lX: no stop signal yet\n", (unsigned long)time(NULL));
		wiomw_get_updates(GET_UPDATES_API_URL, config, str_session_id);
		wiomw_send_updates(SEND_UPDATES_API_URL, config, str_session_id);
		alarm(GET_UPDATES_FREQUENCY);
		sleep_until_signalled();
	}
*/




	/* TODO: Any remaining cleanup goes here. */
	return EX_OK;
}

