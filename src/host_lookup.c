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

#include "host_lookup.h"
#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sysexits.h>
#include <syslog.h>
#include "syslog_syserror.h"
#include "string_helpers.h"

#define DNSMASQ_DUMP_COMMAND "cat %s | awk '{print $2 $4}'"

struct _host_lookup_table_struct {
	char mac_addr[18];
	struct _host_lookup_table_struct* next;
	char* hostname;
};

host_lookup_table_t get_host_lookup_table()
{
	if (CONFIG_OPTION_DNSMASQ_LEASE_LOOKUP) {
		host_lookup_table_t lookup_table = NULL;
		host_lookup_table_t* temp = &lookup_table;
		char command[BUFSIZ];
		FILE* output;
		config_t config = get_configuration();
		snprintf(command, BUFSIZ, DNSMASQ_DUMP_COMMAND, config->dnsmasq_lease_file);
		output = popen(command, "r");
		if (output == NULL) {
			syslog_syserror(LOG_CRIT, "Unable to connect to shell for dnsmasq lookup");
			exit(EX_OSERR);
		} else {
			char line[BUFSIZ];
			while (fgets(line, BUFSIZ, output) != NULL) {
				size_t hostname_length = safe_string_length(line + 17, BUFSIZ - 17);
				if (hostname_length != BUFSIZ - 17) {
					*temp = (host_lookup_table_t)malloc(sizeof(struct _host_lookup_table_struct));
					if (*temp == NULL) {
						syslog_syserror(LOG_EMERG, "Unable to allocate memory");
						exit(EX_OSERR);
					}
					strncpy((*temp)->mac_addr, line, 17);
					(*temp)->mac_addr[17] = '\0';
					(*temp)->hostname = string_chomp_copy(line + 17);
					(*temp)->next = NULL;
					temp = &((*temp)->next);
				}
			}
		}
		pclose(output);
		return lookup_table;
	} else {
		return NULL;
	}
}

char* host_lookup(host_lookup_table_t table, char* mac_addr)
{
	host_lookup_table_t temp = table;
	while (temp != NULL) {
		if (strncasecmp(temp->mac_addr, mac_addr, 18) == 0) {
			return temp->hostname;
		} else {
			temp = temp->next;
		}
	}
	return NULL;
}

void destroy_host_lookup_table(host_lookup_table_t* table)
{
	if (table != NULL) {
		while (*table != NULL) {
			host_lookup_table_t temp = *table;
			*table = temp->next;
			free(temp->hostname);
			free(temp);
		}
	}
}



