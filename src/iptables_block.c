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

#include "block.h"
#include <config.h>
#include <yajl/yajl_tree.h>
#include <string.h>
#include <linux/string.h>
#include <sys/types.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <stdbool.h>
#include <syslog.h>
#include "syslog_syserror.h"
#include "string_helpers.h"

#define JSON_ERROR_BUFFER_LEN 1024
#define IPTABLES_COMMAND_STUB "export TEMPERR='%s'; "\
	"%s -%c FORWARD -m mac --mac-source %s -j DROP 2>$TEMPERR;" \
	"/bin/echo $? `/bin/cat $TEMPERR`; rm $TEMPERR; unset TEMPERR "
#define IPTABLES_ADD_MODIFIER 'I'
#define IPTABLES_DELETE_MODIFIER 'D'


/* TODO: Add iptables check test to autoconf */
#ifdef HAVE_IPTABLES_CHECK
#define IPTABLES_CHECK_MODIFIER 'C'
#else
#define HAVE_IPTABLES_CHECK false
#define IPTABLES_CHECK_MODIFIER 'D'
#endif

#define UNCOMPILED_MAC_REGEX "^([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}$"

void print_json_parse_error(const char* json_error_buffer, const size_t json_error_buffer_len)
{
	if (0 == safe_string_length(json_error_buffer, json_error_buffer_len)
			|| json_error_buffer_len == safe_string_length(json_error_buffer, json_error_buffer_len)) {
		syslog(LOG_CRIT, "Unable to parse block data JSON: Unknown error");
	} else {
		syslog(LOG_CRIT, "Unable to parse block data JSON: %s", json_error_buffer);
	}
}

void apply_blocks(const char* block_json)
{
	yajl_val top;
	yajl_val entry;
	unsigned int i = 0;
	regex_t mac_regex;
	int errcode;
	char json_error_buffer[JSON_ERROR_BUFFER_LEN];

	if (block_json == NULL) {
		syslog(LOG_CRIT, "Invalid string received for block data");
		return;
	}

	errcode = regcomp(&mac_regex, UNCOMPILED_MAC_REGEX, REG_EXTENDED);
	if (errcode != 0) {
		char str_temp[BUFSIZ];
		regerror(errcode, &mac_regex, str_temp, BUFSIZ);
		syslog(LOG_CRIT, "Unable to prepare MAC regex: %s", str_temp);
		return;
	}

	top = yajl_tree_parse(block_json, json_error_buffer, JSON_ERROR_BUFFER_LEN);
	if (top == NULL) {
		print_json_parse_error(json_error_buffer, JSON_ERROR_BUFFER_LEN);
		regfree(&mac_regex);
		return;
	} else if (!YAJL_IS_ARRAY(top)) {
		syslog(LOG_CRIT, "Received block data is not an array, unable to block");
		regfree(&mac_regex);
		return;
	}

	for (i = 0; i < top->u.array.len; i++) {
		const char* mac_path[] = {"macaddress", (const char*)0};
		const char* block_path[] = {"block", (const char*)0};
		yajl_val mac_node;
		yajl_val block_node;
		int errcode;
		entry = top->u.array.values[i];
		if ((mac_node = yajl_tree_get(entry, mac_path, yajl_t_string)) == NULL) {
			syslog(LOG_WARNING, "Block data JSON entry has no MAC address, skipping");
		} else if ((block_node = yajl_tree_get(entry, block_path, yajl_t_string)) == NULL) {
			syslog(LOG_WARNING, "Block data JSON entry has no block status, skipping");
		} else if ((errcode = regexec(&mac_regex, mac_node->u.string, 0, NULL, 0)) == 0) {
			if (strncmp(block_node->u.string, "0", 2) == 0) {
				int errcode = 0;
				char command[BUFSIZ];
				char tempfile[] = "/tmp/wiomw-iptables-error-XXXXXX";
				int tfd = -1;
				if ((tfd = mkstemp(tempfile)) == -1) {
					syslog_syserror(LOG_EMERG, "Unable to create temporary file");
					exit(EX_OSERR);
				}
				snprintf(command, BUFSIZ, IPTABLES_COMMAND_STUB, tempfile, CONFIG_OPTION_IPTABLES_PATH, IPTABLES_DELETE_MODIFIER, YAJL_GET_STRING(mac_node));
				do {
					FILE* output = popen(command, "r");
					if (output == NULL) {
						syslog_syserror(LOG_ERR, "Unable to communicate with shell during device unblocking");
						errcode = -999;
					} else {
						if (fscanf(output, "%d ", &errcode) == EOF) {
							syslog_syserror(LOG_CRIT, "Unable to communicate with shell during device unblocking");
						} else if (errcode != 0 && errcode != 1) {
							char errstring[BUFSIZ];
							if (fgets(errstring, BUFSIZ, output) == NULL) {
								syslog_syserror(LOG_CRIT, "An error occurred while attempting to unblock a MAC address");
							} else {
								syslog(LOG_CRIT, "An error occurred while attempting to unblock a MAC address: Error %d: %s", errcode, errstring);
							}
						}
						if (pclose(output) == -1) {
							syslog_syserror(LOG_CRIT, "Unable to communicate with shell during device unblocking");
							errcode = -999;
						}
					}
				} while (errcode == 0);
				if (close(tfd) == EOF || (remove(tempfile) == -1 && errno != ENOENT)) {
					syslog_syserror(LOG_EMERG, "Unable to remove temporary file");
					exit(EX_OSERR);
				}
			} else {
				int errcode = 0;
				char command[BUFSIZ];
				FILE* output;
				char tempfile[] = "/tmp/wiomw-iptables-error-XXXXXX";
				int tfd = NULL;
				if ((tfd = mkstemp(tempfile)) == -1) {
					syslog_syserror(LOG_EMERG, "Unable to create temporary file");
					exit(EX_OSERR);
				}
				snprintf(command, BUFSIZ, IPTABLES_COMMAND_STUB, tempfile, CONFIG_OPTION_IPTABLES_PATH, IPTABLES_CHECK_MODIFIER, YAJL_GET_STRING(mac_node));
				output = popen(command, "r");
				if (output == NULL) {
					syslog_syserror(LOG_CRIT, "Unable to communicate with shell during device block checking");
				} else {
					if (fscanf(output, "%d ", &errcode) == EOF) {
						syslog_syserror(LOG_CRIT, "Unable to communicate with shell during device block checking");
					} else if (errcode != 0 && errcode != 1) {
						char errstring[BUFSIZ];
						if (fgets(errstring, BUFSIZ, output) == NULL) {
							syslog_syserror(LOG_CRIT, "An error occurred while attempting to check the blocking status of a MAC address");
						} else {
							syslog(LOG_CRIT, "An error occurred while attempting to check the blocking status of a MAC address: Error %d: %s", errcode, errstring);
						}
					}
					if (pclose(output) == -1) {
						syslog_syserror(LOG_CRIT, "Unable to communicate with shell during device block checking");
					}
				}
				if (!HAVE_IPTABLES_CHECK || errcode == 1) {
					snprintf(command, BUFSIZ, IPTABLES_COMMAND_STUB, tempfile, CONFIG_OPTION_IPTABLES_PATH, IPTABLES_ADD_MODIFIER, YAJL_GET_STRING(mac_node));
					output = popen(command, "r");
					if (output == NULL) {
						syslog_syserror(LOG_CRIT, "Unable to communicate with shell during device blocking");
					} else {
						if (fscanf(output, "%d ", &errcode) == EOF) {
							syslog_syserror(LOG_CRIT, "Unable to communicate with shell during device blocking");
						} else if (errcode != 0 && errcode != 1) {
							char errstring[BUFSIZ];
							if (fgets(errstring, BUFSIZ, output) == NULL) {
								syslog_syserror(LOG_CRIT, "An error occurred while attempting to block a MAC address");
							} else {
								syslog(LOG_CRIT, "An error occurred while attempting to block a MAC address: Error %d: %s", errcode, errstring);
							}
						}
						if (pclose(output) == -1) {
							syslog_syserror(LOG_CRIT, "Unable to communicate with shell during device blocking");
						}
					}
				}
				if (close(tfd) == EOF || (remove(tempfile) == -1 && errno != ENOENT)) {
					syslog_syserror(LOG_EMERG, "Unable to remove temporary file");
					exit(EX_OSERR);
				}
			}
		} else if (errcode == REG_NOMATCH) {
			syslog(LOG_CRIT, "Received invalid MAC address in block JSON: (%s)", mac_node->u.string);
		} else {
			syslog_syserror(LOG_CRIT, "Unable to evaluate MAC address regex on block data.");
		}
	}

	yajl_tree_free(top);
	regfree(&mac_regex);
}

