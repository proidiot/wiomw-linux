#include "block.h"

#include <yajl/yajl_tree.h>

#define IPTABLES_COMMAND_STUB "iptables -%c FORWARD -m mac --mac-source %s -j DROP"
#define IPTABLES_ADD_MODIFIER 'I'
#define IPTABLES_DELETE_MODIFIER 'D'
#define UNCOMPILED_MAC_REGEX "^[0-9a-fA-F][0-9a-fA-F]?:[0-9a-fA-F][0-9a-fA-F]?:[0-9a-fA-F][0-9a-fA-F]?:[0-9a-fA-F][0-9a-fA-F]?:[0-9a-fA-F][0-9a-fA-F]?:[0-9a-fA-F][0-9a-fA-F]?$"

void print_json_parse_error(const char* json_error_buffer, const size_t json_error_buffer_len);
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
	char* top_path[] = {(char*)0};
	size_t json_error_buffer_len = 1024;
	char json_error_buffer[json_error_buffer_len];

	if (block_json == NULL) {
		print_error("Invalid string received for block data");
		return;
	}

	top = yajl_tree_parse(block_json, json_error_buffer, json_error_buffer_len);
	if (top == NULL) {
		print_json_parse_error(json_error_buffer, json_error_buffer_len);
		return;
	}

	while ((entry = yajl_tree_get(top, top_path, yajl_t_object)) != NULL) {
		const char* mac_path[] = {"macaddress"};
		const char* block_path[] = {"block"};
		yajl_val mac_node;
		yajl_val block_node;
		int errcode;
		if ((mac_node = yajl_tree_get(entry, mac_path, yajl_t_string)) == NULL) {
			print_error("Block data JSON entry has no MAC address, skipping");
		} else if ((block_node = yajl_tree_get(entry, block_path, yajl_t_number)) == NULL) {
			print_error("Block data JSON entry has no block status, skipping");
		} else if ((errcode = regexec(mac_regex, YAJL_GET_STRING(mac_node), 0, NULL, REG_EXTENDED | REG_ICASE)) == 0) {
			if (YAJL_GET_NUMBER(block_node) == 0) {
				int errcode = 0;
				char command[BUFSIZ];
				snprintf(command, BUFSIZ, IPTABLES_COMMAND_STUB, IPTABLES_DELETE_MODIFIER, YAJL_GET_STRING(mac_node));
				do {
					errcode = system(command);
				} while (errcode == 0);
				if (WEXITSTATUS(errcode) != 1) {
					print_error("An error occurred while attempting to unblock a MAC address.");
				}
			} else {
				int errcode = 0;
				char command[BUFSIZ];
				snprintf(command, BUFSIZ, IPTABLES_COMMAND_STUB, IPTABLES_ADD_MODIFIER, YAJL_GET_STRING(mac_node));
				if ((errcode = system(command)) != 0) {
					print_error("An error occurred while attempting to block a MAC address.");
				}
			}
		} else if (errcode == REG_NOMATCH) {
			print_error("Received invalid MAC address in block JSON");
		} else {
			print_syserror("Unable to evaluate MAC address regex on block data.");
		}
		i++;
		top_path[0] = (char*)i;
	}
}

