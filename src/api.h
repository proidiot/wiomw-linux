#ifndef _WIOMW_API_H_
#define _WIOMW_API_H_

#include "configuration.h"

void wiomw_login(config_t* config);

void send_config(config_t* config);

void sync_block(config_t* config);

void send_subnet_and_devices(config_t* config);

#endif
