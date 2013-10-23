#ifndef _WIOMW_HOST_LOOKUP_H_
#define _WIOMW_HOST_LOOKUP_H_

#include "configuration.h"

typedef struct _host_lookup_table_struct* host_lookup_table_t;

host_lookup_table_t get_host_lookup_table(config_t* config);

char* host_lookup(host_lookup_table_t table, char* mac_addr);

void destroy_host_lookup_table(host_lookup_table_t* table);

#endif
