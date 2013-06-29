#ifndef _WIOMW_API_H_
#define _WIOMW_API_H_

#include "configuration.h"

void wiomw_login(config_t* config);

/* TODO: make a better prototype for this function. */
void wiomw_get_updates(config_t* config);

/* TODO: make a better prototype for this function. */
void wiomw_send_updates(config_t* config);

#endif
