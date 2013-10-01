#include "block.h"

#include <yajl/yajl_tree.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include "print_error.h"

#define JSON_ERROR_BUFFER_LEN 1024
#define IPTABLES_COMMAND_STUB "export TEMPERR=`/bin/mktemp --tmpdir=/tmp`;"\
	"/sbin/iptables -%c FORWARD -m mac --mac-source %s -j DROP 2>$TEMPERR;" \
	"/bin/echo $? `/bin/cat $TEMPERR`; rm $TEMPERR; unset TEMPERR "
#define IPTABLES_ADD_MODIFIER 'I'
#define IPTABLES_CHECK_MODIFIER 'C'
#define IPTABLES_DELETE_MODIFIER 'D'
#define UNCOMPILED_MAC_REGEX "^([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}$"

void print_json_parse_error(const char* json_error_buffer, const size_t json_error_buffer_len)
{
	if (strnlen(json_error_buffer, json_error_buffer_len) == 0
			|| strnlen(json_error_buffer, json_error_buffer_len) == json_error_buffer_len) {
		print_error("Unable to parse block data JSON: Unknown error");
	} else {
		print_error("Unable to parse block data JSON: %s", json_error_buffer);
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
		print_error("Invalid string received for block data");
		return;
	}

	errcode = regcomp(&mac_regex, UNCOMPILED_MAC_REGEX, REG_EXTENDED);
	if (errcode != 0) {
		char str_temp[BUFSIZ];
		regerror(errcode, &mac_regex, str_temp, BUFSIZ);
		print_error("Unable to prepare MAC regex: %s", str_temp);
		return;
	}

	top = yajl_tree_parse(block_json, json_error_buffer, JSON_ERROR_BUFFER_LEN);
	if (top == NULL) {
		print_json_parse_error(json_error_buffer, JSON_ERROR_BUFFER_LEN);
		regfree(&mac_regex);
		return;
	} else if (!YAJL_IS_ARRAY(top)) {
		print_error("Received block data is not an array, unable to block");
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
			print_error("Block data JSON entry has no MAC address, skipping");
		} else if ((block_node = yajl_tree_get(entry, block_path, yajl_t_string)) == NULL) {
			print_error("Block data JSON entry has no block status, skipping");
		} else if ((errcode = regexec(&mac_regex, mac_node->u.string, 0, NULL, 0)) == 0) {
			if (strncmp(block_node->u.string, "0", 2) == 0) {
				int errcode = 0;
				char command[BUFSIZ];
				snprintf(command, BUFSIZ, IPTABLES_COMMAND_STUB, IPTABLES_DELETE_MODIFIER, YAJL_GET_STRING(mac_node));
				do {
					FILE* output = popen(command, "r");
					if (output == NULL) {
						print_syserror("An error occurred while preparing to unblock a MAC address");
						errcode = -999;
					} else {
						if (fscanf(output, "%d ", &errcode) == EOF) {
							print_syserror("An error occurred while attempting to unblock a MAC address");
						} else if (errcode != 0 && errcode != 1) {
							char errstring[BUFSIZ];
							if (fgets(errstring, BUFSIZ, output) == NULL) {
								print_syserror("An error occurred while attempting to unblock a MAC address");
							} else {
								print_error("An error occurred while attempting to unblock a MAC address: Error %d: %s", errcode, errstring);
							}
						}
						if (pclose(output) == -1) {
							print_syserror("An error occurred while cleaning up after unblocking a MAC address");
							errcode = -999;
						}
					}
				} while (errcode == 0);
			} else {
				int errcode = 0;
				char command[BUFSIZ];
				FILE* output;
				snprintf(command, BUFSIZ, IPTABLES_COMMAND_STUB, IPTABLES_CHECK_MODIFIER, YAJL_GET_STRING(mac_node));
				output = popen(command, "r");
				if (output == NULL) {
					print_syserror("An error occurred while preparing to check a MAC address");
				} else {
					if (fscanf(output, "%d ", &errcode) == EOF) {
						print_syserror("An error occurred while attempting to check a MAC address");
					} else if (errcode != 0 && errcode != 1) {
						char errstring[BUFSIZ];
						if (fgets(errstring, BUFSIZ, output) == NULL) {
							print_syserror("An error occurred while attempting to check a MAC address");
						} else {
							print_error("An error occurred while attempting to check a MAC address: Error %d: %s", errcode, errstring);
						}
					}
					if (pclose(output) == -1) {
						print_syserror("An error occurred while cleaning up after checking a MAC address");
					}
				}
				if (errcode == 1) {
					snprintf(command, BUFSIZ, IPTABLES_COMMAND_STUB, IPTABLES_ADD_MODIFIER, YAJL_GET_STRING(mac_node));
					output = popen(command, "r");
					if (output == NULL) {
						print_syserror("An error occurred while preparing to block a MAC address");
					} else {
						if (fscanf(output, "%d ", &errcode) == EOF) {
							print_syserror("An error occurred while attempting to block a MAC address");
						} else if (errcode != 0 && errcode != 1) {
							char errstring[BUFSIZ];
							if (fgets(errstring, BUFSIZ, output) == NULL) {
								print_syserror("An error occurred while attempting to block a MAC address");
							} else {
								print_error("An error occurred while attempting to block a MAC address: Error %d: %s", errcode, errstring);
							}
						}
						if (pclose(output) == -1) {
							print_syserror("An error occurred while cleaning up after blocking a MAC address");
						}
					}
				}
			}
		} else if (errcode == REG_NOMATCH) {
			print_error("Received invalid MAC address in block JSON: (%s)", mac_node->u.string);
		} else {
			print_syserror("Unable to evaluate MAC address regex on block data.");
		}
	}

	yajl_tree_free(top);
	regfree(&mac_regex);
}
