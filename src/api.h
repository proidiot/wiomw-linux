#ifndef _WIOMW_API_H_
#define _WIOMW_API_H_

#include "configuration.h"

void wiomw_login(config_t* config);

/* TODO: make a better prototype for this function. */
void sync_block(config_t* config);

/* TODO: make a better prototype for this function. */
void send_devices(config_t* config);

#endif
