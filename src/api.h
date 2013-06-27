#ifndef _WIOMW_API_H_
#define _WIOMW_API_H_

#include "configuration.h"

char* wiomw_login(const char* const str_url, const config_t config);

/* TODO: make a better prototype for this function. */
void wiomw_get_updates(const char* const str_url, const config_t config, const char* const str_session_id);

/* TODO: make a better prototype for this function. */
void wiomw_send_updates(const char* const str_url, const config_t config, const char* const str_session_id);

#endif
