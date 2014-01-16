#include <config.h>
#include "configuration.h"
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <string.h>
#include <linux/string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include "print_error.h"
#include "string_helpers.h"

#ifndef HAVE_NVRAM_GET
char* nvram_get(char* name)
{
	char command[BUFSIZ];
	char* result = NULL;
	long reslen;
	FILE* output;
	snprintf(command, BUFSIZ, NVRAM_COMMAND " get %s", name);
	output = popen(command, "r");
	if (feof(output)) {
		pclose(output);
	} else if (-1 == fseek(output, 0, SEEK_END) || -1 == (reslen = ftell(output)) || -1 == fseek(output, 0, SEEK_SET)) {
		print_syserror("Error while reading from nvram");
		exit(EX_OSERR);
	} else if (NULL == (result = (char*)malloc((size_t)reslen))) {
		print_syserror("Unable to allocate memory for nvram_get result");
		exit(EX_OSERR);
	} else if ((size_t)reslen != fread(result, 1, reslen, output)) {
		print_syserror("Error while reading from nvram");
		exit(EX_OSERR);
	} else {
		pclose(output);
	}
	return result;
}
#endif

#define ALLOW_URL_OVERRIDES 0

#ifndef DNSMASQ_LEASE_FILE
#define DNSMASQ_LEASE_FILE "/var/lib/misc/dnsmas.lease"
#endif

#define USERNAME_CONFIG_PREFIX "USERNAME"
#define PASSHASH_CONFIG_PREFIX "PASSHASH"
#define AGENTKEY_CONFIG_PREFIX "AGENTKEY"
#define NETWORKS_CONFIG_PREFIX "NETWORKS"
#define IFACE_BLACKLIST_REGEX_CONFIG_PREFIX "IFACE_BLACKLIST_REGEX"
#define LOGIN_URL_CONFIG_PREFIX "LOGIN_URL"
#define CONFIG_AGENT_URL_CONFIG_PREFIX "CONFIG_AGENT_URL"
#define SYNC_BLOCK_URL_CONFIG_PREFIX "SYNC_BLOCK_URL"
#define SEND_URL_CONFIG_PREFIX "SEND_DEVICES_URL"
#define IGNORE_BLACKLIST_IFACE_CONFIG_PREFIX "COMPLETELY_IGNORE_BLACKLIST_IFACES"
#define SHOW_UNREACHABLE_NEIGHS_CONFIG_PREFIX "SEND_UNREACHABLE_NEIGHS"
#define SHOW_KNOWN_BLACKLIST_IFACE_NEIGHS_CONFIG_PREFIX "SEND_KNOWN_NEIGHS_BEHIND_BLACKLIST_IFACES"
#define SHOW_DOWN_IFACE_CONFIG_PREFIX "SEND_DOWN_IFACES"
#define SHOW_SECONDARY_IFACE_ADDR_CONFIG_PREFIX "SEND_SECONDARY_IFACE_ADDRS"
#define BLACKLIST_OVERRIDES_NETWORKS_CONFIG_PREFIX "BLACKLIST_OVERRIDES_NETWORKS"
#define AUTOSCAN_CONFIG_PREFIX "AUTOSCAN"
#define ALLOW_BLOCKING_CONFIG_PREFIX "ALLOW_BLOCKING"
/* TODO: add config option for identity/broadcast inclusion for NETWORKS */
/* TODO: add config option for identity/broadcast inclusion for real? */
/* TODO: add config option for config file overwrite (add warnings) */

#define CONFIG_ERROR_STRING_PREFIX "Configuration error: "
#define NVRAM_PREFIX "wiomw"

char* find_config_value(char* source, const char* prefix)
{
	size_t i = 0;

	while (source[i] == ' ' || source[i] == '\t') {
		i++;
	}

	if (strncmp(source, prefix, strlen(prefix)) != 0) {
		return NULL;
	}

	i += strlen(prefix);

	while (source[i] == ' ' || source[i] == '\t') {
		i++;
	}

	if (source[i] != '=') {
		return NULL;
	} else {
		return source + i + 1;
	}
}

config_t get_configuration(int argc, char** argv)
{
	FILE* config_file;
	char raw_line[MAX_CONFIG_LINE_LENGTH + 2];
	config_t config;
	char* config_file_location = CONFIG_FILE_LOCATION; /* Maybe also allow this to be set on command line? */
	bool config_username_is_set = false;
	bool config_passhash_is_set = false;
	bool config_agentkey_is_set = false;
	bool config_iface_blacklist_regex_is_set = false;
	bool config_login_url_is_set = false;
	bool config_config_agent_url_is_set = false;
	bool config_sync_block_url_is_set = false;
	bool config_send_devices_url_is_set = false;
	bool config_networks_is_set = false;
	bool config_ignore_blacklist_iface_is_set = false;
	bool config_show_unreachable_neighs_is_set = false;
	bool config_show_known_blacklist_iface_neighs_is_set = false;
	bool config_show_down_iface_is_set = false;
	bool config_show_secondary_iface_addr_is_set = false;
	bool config_blacklist_overrides_networks_is_set = false;
	bool config_autoscan_is_set = false;
	bool config_allow_blocking_is_set = false;
	/*bool config_dnsmasq_lease_file_is_set = false;*/
	bool config_file_location_is_set = false;


	/* Default config values
	 * (If a value must be specified, set bad values here and check if they match after the file is closed.) */
	config.username = NULL;
	config.passhash = NULL;
	config.agentkey = NULL;
	config.iface_blacklist_regex = NULL;
	config.login_url = string_chomp_copy(LOGIN_API_URL);
	config.config_agent_url = string_chomp_copy(CONFIG_AGENT_API_URL);
	config.sync_block_url = string_chomp_copy(SYNC_BLOCK_API_URL);
	config.send_devices_url = string_chomp_copy(SEND_DEVICES_API_URL);
	config.networks = NULL;
	config.ignore_blacklist_iface = true;
	config.show_unreachable_neighs = false;
	config.show_known_blacklist_iface_neighs = false;
	config.show_down_iface = false;
	config.show_secondary_iface_addr = false;
	config.blacklist_overrides_networks = true;
	config.autoscan = true;
	config.allow_blocking = true;
	config.dnsmasq_lease_file = DNSMASQ_LEASE_FILE;
	config.session_id = NULL;

	if (argc > 1) {
		char c = '\0';
		while (-1 != (c = getopt(argc, argv, "u:p:a:c:"))) {
			switch (c) {
			case 'u':
				config.username = optarg;
				config_username_is_set = true;
				break;
			case 'p':
				config.passhash = optarg;
				config_passhash_is_set = true;
				break;
			case 'a':
				config.agentkey = optarg;
				config_agentkey_is_set = true;
				break;
			case 'c':
				config_file_location = optarg;
				config_file_location_is_set = true;
				break;
			case '?':
				print_error("Usage: %s [ -u USERNAME ] [ -p PASSHASH ] [ -a AGENTKEY ] [ -c CONFIG_FILE_PATH ]", argv[0]);
				break;
			default:
				print_error("Usage: %s [ -u USERNAME ] [ -p PASSHASH ] [ -a AGENTKEY ] [ -c CONFIG_FILE_PATH ]", argv[0]);
			}
		}
	}

	if (USE_NVRAM_CONFIG) {
		char* nvram_value = NULL;

		if (!config_username_is_set && NULL != (nvram_value = nvram_get(NVRAM_PREFIX "_username"))) {
			config_username_is_set = true;
			config.username = nvram_value;
		}
		if (!config_passhash_is_set && NULL != (nvram_value = nvram_get(NVRAM_PREFIX "_passhash"))) {
			config_passhash_is_set = true;
			config.passhash = nvram_value;
		}
		if (!config_agentkey_is_set && NULL != (nvram_value = nvram_get(NVRAM_PREFIX "_agentkey"))) {
			config_agentkey_is_set = true;
			config.agentkey = nvram_value;
		}
		if (!config_file_location_is_set && NULL != (nvram_value = nvram_get(NVRAM_PREFIX "_config_path"))) {
			config_file_location_is_set = true;
			config_file_location = nvram_value;
		}
	}

	/* Time to get the file and read the data we want from it. */
	config_file = fopen(config_file_location, "r");
	if (config_file == NULL) {
		print_syserror(CONFIG_ERROR_STRING_PREFIX "Unable to open the configuration file (%s)", config_file_location);
	} else {
		while (fgets(raw_line, MAX_CONFIG_LINE_LENGTH + 2, config_file) != NULL) {
			char* value = NULL;
	
			char* current_line = raw_line;
			while (current_line[0] == ' ' || current_line[0] == '\t') {
				current_line++;
			}
	
			if (current_line[0] == '\0'	|| current_line[0] == '\n' || current_line[0] == '#') {
				/* This was either an empty or comment line, so it should be safe to ignore. */
			} else if (strlen(current_line) > MAX_CONFIG_LINE_LENGTH && current_line[MAX_CONFIG_LINE_LENGTH] != '\n') {
				print_error(
						CONFIG_ERROR_STRING_PREFIX "A non-comment line in the configuration file has more than %d "
						"characters",
						MAX_CONFIG_LINE_LENGTH);
				fclose(config_file);
				/* TODO: Any remaining cleanup goes here. */
				exit(EX_CONFIG);
			} else if ((value = find_config_value(current_line, USERNAME_CONFIG_PREFIX)) != NULL) {
				if (!config_username_is_set) {
					config_username_is_set = true;
					if ((config.username = string_chomp_copy(value)) == NULL) {
						print_error(CONFIG_ERROR_STRING_PREFIX USERNAME_CONFIG_PREFIX " must not be empty");
						exit(EX_CONFIG);
					}
				}
			} else if ((value = find_config_value(current_line, PASSHASH_CONFIG_PREFIX)) != NULL) {
				if (!config_passhash_is_set) {
					config_passhash_is_set = true;
					if ((config.passhash = string_chomp_copy(value)) == NULL) {
						print_error(CONFIG_ERROR_STRING_PREFIX PASSHASH_CONFIG_PREFIX " must not be empty");
						exit(EX_CONFIG);
					}
				}
			} else if ((value = find_config_value(current_line, AGENTKEY_CONFIG_PREFIX)) != NULL) {
				if (!config_agentkey_is_set) {
					config_agentkey_is_set = true;
					if ((config.agentkey = string_chomp_copy(value)) == NULL) {
						print_error(CONFIG_ERROR_STRING_PREFIX AGENTKEY_CONFIG_PREFIX " must not be empty");
						exit(EX_CONFIG);
					}
				}
			} else if ((value = find_config_value(current_line, IFACE_BLACKLIST_REGEX_CONFIG_PREFIX)) != NULL) {
				if (!config_iface_blacklist_regex_is_set) {
					config_iface_blacklist_regex_is_set = true;
					config.iface_blacklist_regex = string_chomp_copy(value);
				}
			} else if ((value = find_config_value(current_line, NETWORKS_CONFIG_PREFIX)) != NULL) {
				if (!config_networks_is_set) {
					print_error("Support for " NETWORKS_CONFIG_PREFIX " is coming soon.");
					exit(EX_CONFIG);
				}
			} else if ((value = find_config_value(current_line, LOGIN_URL_CONFIG_PREFIX)) != NULL) {
				if (!config_login_url_is_set) {
					config_login_url_is_set = true;
					if (ALLOW_URL_OVERRIDES) {
						char* new_url = string_chomp_copy(value);
						if (new_url != NULL) {
							free(config.login_url);
							config.login_url = new_url;
						}
					} else {
						print_error(CONFIG_ERROR_STRING_PREFIX LOGIN_URL_CONFIG_PREFIX " cannot be overriden at this time");
						exit(EX_CONFIG);
					}
				}
			} else if ((value = find_config_value(current_line, CONFIG_AGENT_URL_CONFIG_PREFIX)) != NULL) {
				if (!config_config_agent_url_is_set) {
					config_config_agent_url_is_set = true;
					if (ALLOW_URL_OVERRIDES) {
						char* new_url = string_chomp_copy(value);
						if (new_url != NULL) {
							free(config.config_agent_url);
							config.config_agent_url = new_url;
						}
					} else {
						print_error(CONFIG_ERROR_STRING_PREFIX CONFIG_AGENT_URL_CONFIG_PREFIX " cannot be overriden at this time");
						exit(EX_CONFIG);
					}
				}
			} else if ((value = find_config_value(current_line, SYNC_BLOCK_URL_CONFIG_PREFIX)) != NULL) {
				if (!config_sync_block_url_is_set) {
					config_sync_block_url_is_set = true;
					if (ALLOW_URL_OVERRIDES) {
						char* new_url = string_chomp_copy(value);
						if (new_url != NULL) {
							free(config.sync_block_url);
							config.sync_block_url = new_url;
						}
					} else {
						print_error(CONFIG_ERROR_STRING_PREFIX SYNC_BLOCK_URL_CONFIG_PREFIX " cannot be overriden at this time");
						exit(EX_CONFIG);
					}
				}
			} else if ((value = find_config_value(current_line, SEND_URL_CONFIG_PREFIX)) != NULL) {
				if (!config_send_devices_url_is_set) {
					config_send_devices_url_is_set = true;
					if (ALLOW_URL_OVERRIDES) {
						char* new_url = string_chomp_copy(value);
						if (new_url != NULL) {
							free(config.send_devices_url);
							config.send_devices_url = new_url;
						}
					} else {
						print_error(CONFIG_ERROR_STRING_PREFIX SEND_URL_CONFIG_PREFIX " cannot be overriden at this time");
						exit(EX_CONFIG);
					}
				}
			} else if ((value = find_config_value(current_line, IGNORE_BLACKLIST_IFACE_CONFIG_PREFIX)) != NULL) {
				if (!config_ignore_blacklist_iface_is_set) {
					int result = parse_bool(value);
					config_ignore_blacklist_iface_is_set = true;
					if (result < 0) {
						print_syserror(CONFIG_ERROR_STRING_PREFIX "Unable to read a boolean value for " IGNORE_BLACKLIST_IFACE_CONFIG_PREFIX);
						exit(EX_CONFIG);
					} else {
						config.ignore_blacklist_iface = (result == 0)? false : true;
					}
				}
			} else if ((value = find_config_value(current_line, SHOW_UNREACHABLE_NEIGHS_CONFIG_PREFIX)) != NULL) {
				if (!config_show_unreachable_neighs_is_set) {
					int result = parse_bool(value);
					config_show_unreachable_neighs_is_set = true;
					if (result < 0) {
						print_syserror(CONFIG_ERROR_STRING_PREFIX "Unable to read a boolean value for " SHOW_UNREACHABLE_NEIGHS_CONFIG_PREFIX);
						exit(EX_CONFIG);
					} else {
						config.show_unreachable_neighs = (result == 0)? false : true;
					}
				}
			} else if ((value = find_config_value(current_line, SHOW_KNOWN_BLACKLIST_IFACE_NEIGHS_CONFIG_PREFIX)) != NULL) {
				if (!config_show_known_blacklist_iface_neighs_is_set) {
					int result = parse_bool(value);
					config_show_known_blacklist_iface_neighs_is_set = true;
					if (result < 0) {
						print_syserror(CONFIG_ERROR_STRING_PREFIX "Unable to read a boolean value for " SHOW_KNOWN_BLACKLIST_IFACE_NEIGHS_CONFIG_PREFIX);
						exit(EX_CONFIG);
					} else {
						config.show_known_blacklist_iface_neighs = (result == 0)? false : true;
					}
				}
			} else if ((value = find_config_value(current_line, SHOW_DOWN_IFACE_CONFIG_PREFIX)) != NULL) {
				if (!config_show_down_iface_is_set) {
					int result = parse_bool(value);
					config_show_down_iface_is_set = true;
					if (result < 0) {
						print_syserror(CONFIG_ERROR_STRING_PREFIX "Unable to read a boolean value for " SHOW_DOWN_IFACE_CONFIG_PREFIX);
						exit(EX_CONFIG);
					} else {
						config.show_down_iface = (result == 0)? false : true;
					}
				}
			} else if ((value = find_config_value(current_line, SHOW_SECONDARY_IFACE_ADDR_CONFIG_PREFIX)) != NULL) {
				if (!config_show_secondary_iface_addr_is_set) {
					int result = parse_bool(value);
					config_show_secondary_iface_addr_is_set = true;
					if (result < 0) {
						print_syserror(CONFIG_ERROR_STRING_PREFIX "Unable to read a boolean value for " SHOW_SECONDARY_IFACE_ADDR_CONFIG_PREFIX);
						exit(EX_CONFIG);
					} else {
						config.show_secondary_iface_addr = (result == 0)? false : true;
					}
				}
			} else if ((value = find_config_value(current_line, BLACKLIST_OVERRIDES_NETWORKS_CONFIG_PREFIX)) != NULL) {
				if (!config_blacklist_overrides_networks_is_set) {
					int result = parse_bool(value);
					config_blacklist_overrides_networks_is_set = true;
					if (result < 0) {
						print_syserror(CONFIG_ERROR_STRING_PREFIX "Unable to read a boolean value for " BLACKLIST_OVERRIDES_NETWORKS_CONFIG_PREFIX);
						exit(EX_CONFIG);
					} else {
						config.blacklist_overrides_networks = (result == 0)? false : true;
					}
				}
			} else if ((value = find_config_value(current_line, AUTOSCAN_CONFIG_PREFIX)) != NULL) {
				if (!config_autoscan_is_set) {
					int result = parse_bool(value);
					config_autoscan_is_set = true;
					if (result < 0) {
						print_syserror(CONFIG_ERROR_STRING_PREFIX "Unable to read a boolean value for " AUTOSCAN_CONFIG_PREFIX);
						exit(EX_CONFIG);
					} else {
						config.autoscan = (result == 0)? false : true;
					}
				}
			} else if ((value = find_config_value(current_line, ALLOW_BLOCKING_CONFIG_PREFIX)) != NULL) {
				if (!config_allow_blocking_is_set) {
					int result = parse_bool(value);
					config_allow_blocking_is_set = true;
					if (result < 0) {
						print_syserror(CONFIG_ERROR_STRING_PREFIX "Unable to read a boolean value for " ALLOW_BLOCKING_CONFIG_PREFIX);
						exit(EX_CONFIG);
					} else {
						config.allow_blocking = (result == 0)? false : true;
					}
				}
			} /* TODO: Any future configuration checks go here. */
		}
		if (!feof(config_file)) {
			/* This perror() call must happen as soon after fgets() as possible, so defer anything other than feof() until later. */
			print_syserror(
					CONFIG_ERROR_STRING_PREFIX "An error occured while reading the configuration file (%s)",
					config_file_location);
		}
	
		/* We should have everything we need now, so let's give the kernel it's file handle back. */
		fclose(config_file);
	}

	if (config.username == NULL) {
		print_error(CONFIG_ERROR_STRING_PREFIX USERNAME_CONFIG_PREFIX " was not specified");
		exit(EX_CONFIG);
	}
	if (config.passhash == NULL) {
		print_error(CONFIG_ERROR_STRING_PREFIX PASSHASH_CONFIG_PREFIX " was not specified");
		exit(EX_CONFIG);
	}
	if (config.agentkey == NULL) {
		print_error(CONFIG_ERROR_STRING_PREFIX AGENTKEY_CONFIG_PREFIX " was not specified");
		exit(EX_CONFIG);
	}

	return config;
}

