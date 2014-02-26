/**
 * Copyright 2013, 2014 Who Is On My WiFi.
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

#ifndef _WIOMW_HOST_LOOKUP_H_
#define _WIOMW_HOST_LOOKUP_H_

#include "configuration.h"

typedef struct _host_lookup_table_struct* host_lookup_table_t;

host_lookup_table_t get_host_lookup_table(config_t* config);

char* host_lookup(host_lookup_table_t table, char* mac_addr);

void destroy_host_lookup_table(host_lookup_table_t* table);

#endif
