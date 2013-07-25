#include <config.h>
#include "configuration.h"
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <string.h>
#include <stdbool.h>
#include "print_error.h"

#define USERNAME_CONFIG_PREFIX "USERNAME="
#define PASSHASH_CONFIG_PREFIX "PASSHASH="
#define NETWORKS_CONFIG_PREFIX "NETWORKS="
#define IFACE_BLACKLIST_REGEX_CONFIG_PREFIX "IFACE_BLACKLIST_REGEX="
#define LOGIN_URL_CONFIG_PREFIX "LOGIN_URL="
#define GET_URL_CONFIG_PREFIX "GET_DEVICES_URL="
#define SEND_URL_CONFIG_PREFIX "SEND_DEVICES_URL="

#define CONFIG_ERROR_STRING_PREFIX "Configuration error: "

config_t get_configuration(int argc, char** argv)
{
	/* Extra characters needed to hold the newline and null. */
	char str_current_line[MAX_CONFIG_LINE_LENGTH + 2];
	char str_username[MAX_USERNAME_LENGTH + 2];
	char str_passhash[MAX_PASSHASH_LENGTH + 2];
	char str_iface_blacklist_regex[MAX_IFACE_BLACKLIST_REGEX_LENGTH + 2];
	char str_login_url[MAX_API_URL_LENGTH + 2];
	char str_get_url[MAX_API_URL_LENGTH + 2];
	char str_send_url[MAX_API_URL_LENGTH + 2];
	FILE* config_file;
	config_t config;
	int bool_valid_config = true;
	char* config_file_location = CONFIG_FILE_LOCATION; /* Maybe also allow this to be set on command line? */

	if (argc > 1) {
		print_error("Command line arguments not yet supported");
		exit(EX_USAGE);
	} else if (argv == NULL || argv[0] == NULL) { /* Frivolous check for now because the compiler was annoying me. */
		print_error("Something strange is going on with argv");
		exit(EX_OSERR);
	}

	/* The null at the beginning initializes the strings safely. */
	str_username[0] = '\0';
	str_passhash[0] = '\0';
	str_iface_blacklist_regex[0] = '\0';
	str_login_url[0] = '\0';
	str_get_url[0] = '\0';
	str_send_url[0] = '\0';

	/* The null beyond the acceptable size will be used to safely check if the strings from the file were too long. */
	str_username[MAX_USERNAME_LENGTH + 1] = '\0';
	str_passhash[MAX_PASSHASH_LENGTH + 1] = '\0';
	str_iface_blacklist_regex[MAX_IFACE_BLACKLIST_REGEX_LENGTH + 1] = '\0';
	str_login_url[MAX_API_URL_LENGTH + 1] = '\0';
	str_get_url[MAX_API_URL_LENGTH + 1] = '\0';
	str_send_url[MAX_API_URL_LENGTH + 1] = '\0';

	/* Time to get the file and read the data we want from it. */
	config_file = fopen(config_file_location, "r");
	if (config_file == NULL) {
		print_syserror(CONFIG_ERROR_STRING_PREFIX "Unable to open the configuration file (%s)", config_file_location);

		/* TODO: Any remaining cleanup goes here. */
		exit(EX_CONFIG);
	}

	while (fgets(str_current_line, MAX_CONFIG_LINE_LENGTH + 2, config_file) != NULL) {
		if (str_current_line[0] == '\0'	|| str_current_line[0] == '\n' || str_current_line[0] == '#') {
			/* This was either an empty or comment line, so it should be safe to ignore. */
		} else if (strlen(str_current_line) > MAX_CONFIG_LINE_LENGTH && str_current_line[MAX_CONFIG_LINE_LENGTH] != '\n') {
			print_error(
					CONFIG_ERROR_STRING_PREFIX "A non-comment line in the configuration file has more than %d "
					"characters",
					MAX_CONFIG_LINE_LENGTH);
			fclose(config_file);
			/* TODO: Any remaining cleanup goes here. */
			exit(EX_CONFIG);
		} else if (strncmp(str_current_line, USERNAME_CONFIG_PREFIX, strlen(USERNAME_CONFIG_PREFIX)) == 0) {
			strncpy(str_username, str_current_line + strlen(USERNAME_CONFIG_PREFIX), MAX_USERNAME_LENGTH + 1);
		} else if (strncmp(str_current_line, PASSHASH_CONFIG_PREFIX, strlen(PASSHASH_CONFIG_PREFIX)) == 0) {
			strncpy(str_passhash, str_current_line + strlen(PASSHASH_CONFIG_PREFIX), MAX_PASSHASH_LENGTH + 1);
		} else if (strncmp(
				str_current_line,
				IFACE_BLACKLIST_REGEX_CONFIG_PREFIX,
				strlen(IFACE_BLACKLIST_REGEX_CONFIG_PREFIX)) == 0) {
			strncpy(
					str_iface_blacklist_regex,
					str_current_line + strlen(IFACE_BLACKLIST_REGEX_CONFIG_PREFIX),
					MAX_IFACE_BLACKLIST_REGEX_LENGTH + 1);
		} else if (strncmp(str_current_line, LOGIN_URL_CONFIG_PREFIX, strlen(LOGIN_URL_CONFIG_PREFIX)) == 0) {
			strncpy(str_login_url, str_current_line + strlen(LOGIN_URL_CONFIG_PREFIX), MAX_API_URL_LENGTH + 1);
		} else if (strncmp(str_current_line, GET_URL_CONFIG_PREFIX, strlen(GET_URL_CONFIG_PREFIX)) == 0) {
			strncpy(str_get_url, str_current_line + strlen(GET_URL_CONFIG_PREFIX), MAX_API_URL_LENGTH + 1);
		} else if (strncmp(str_current_line, SEND_URL_CONFIG_PREFIX, strlen(SEND_URL_CONFIG_PREFIX)) == 0) {
			strncpy(str_send_url, str_current_line + strlen(SEND_URL_CONFIG_PREFIX), MAX_API_URL_LENGTH + 1);
		} /* TODO: Any future configuration checks go here. */
	}
	if (!feof(config_file)) {
		/* This perror() call must happen as soon after fgets() as possible, so defer anything other than feof() until later. */
		print_syserror(
				CONFIG_ERROR_STRING_PREFIX "An error occured while reading the configuration file (%s)",
				config_file_location);
		fclose(config_file);
		/* TODO: Any remaining cleanup goes here. */
		exit(EX_CONFIG);
	}


	/* We should have everything we need now, so let's give the kernel it's file handle back. */
	fclose(config_file);


	/* A successful call to fgets() preserves the newline at the end of the string (if present), and we don't want it. */
	if (str_username[0] == '\0') {
		print_error(CONFIG_ERROR_STRING_PREFIX "USERNAME was not properly specified");
		bool_valid_config = false;
	} else if (str_username[strlen(str_username) - 1] == '\n') {
		str_username[strlen(str_username) - 1] = '\0';
	} else if (strlen(str_username) > MAX_USERNAME_LENGTH) {
		print_error(CONFIG_ERROR_STRING_PREFIX "USERNAME is too long");
		bool_valid_config = false;
	}
	if (str_passhash[0] == '\0') {
		print_error(CONFIG_ERROR_STRING_PREFIX "PASSHASH was not properly specified");
		bool_valid_config = false;
	} else if (str_passhash[strlen(str_passhash) - 1] == '\n') {
		str_passhash[strlen(str_passhash) - 1] = '\0';
	} else if (strlen(str_passhash) > MAX_PASSHASH_LENGTH) {
		print_error(CONFIG_ERROR_STRING_PREFIX "PASSHASH is too long");
		bool_valid_config = false;
	}
	if (str_iface_blacklist_regex[0] != '\0' && str_iface_blacklist_regex[strlen(str_iface_blacklist_regex) - 1] == '\n') {
		str_iface_blacklist_regex[strlen(str_iface_blacklist_regex) - 1] = '\0';
	} else if (strlen(str_iface_blacklist_regex) > MAX_IFACE_BLACKLIST_REGEX_LENGTH) {
		print_error(CONFIG_ERROR_STRING_PREFIX "IFACE_BLACKLIST_REGEX is too long");
		bool_valid_config = false;
	}
	if (str_login_url[0] != '\0' && str_login_url[strlen(str_login_url) - 1] == '\n') {
		str_login_url[strlen(str_login_url) - 1] = '\0';
	} else if (strlen(str_login_url) > MAX_API_URL_LENGTH) {
		print_error(CONFIG_ERROR_STRING_PREFIX "LOGIN_URL is too long");
		bool_valid_config = false;
	}
	if (str_get_url[0] != '\0' && str_get_url[strlen(str_get_url) - 1] == '\n') {
		str_get_url[strlen(str_get_url) - 1] = '\0';
	} else if (strlen(str_get_url) > MAX_API_URL_LENGTH) {
		print_error(CONFIG_ERROR_STRING_PREFIX "GET_DEVICES_URL is too long");
		bool_valid_config = false;
	}
	if (str_send_url[0] != '\0' && str_send_url[strlen(str_send_url) - 1] == '\n') {
		str_send_url[strlen(str_send_url) - 1] = '\0';
	} else if (strlen(str_send_url) > MAX_API_URL_LENGTH) {
		print_error(CONFIG_ERROR_STRING_PREFIX "SEND_DEVICES_URL is too long");
		bool_valid_config = false;
	}


	/* Exit now if the configuration is invalid. */
	if (!bool_valid_config) {
		/* TODO: Any remaining cleanup goes here. */
		exit(EX_CONFIG);
	}

	/* Copy the config strings into the config struct now that we know they're fine. */
	strcpy(config.str_username, str_username);
	strcpy(config.str_passhash, str_passhash);
	strcpy(config.str_iface_blacklist_regex, str_iface_blacklist_regex);
	if (str_login_url[0] == '\0') {
		strcpy(config.str_login_url, LOGIN_API_URL);
	} else {
		strcpy(config.str_login_url, str_login_url);
	}
	if (str_get_url[0] == '\0') {
		strcpy(config.str_get_url, GET_UPDATES_API_URL);
	} else {
		strcpy(config.str_get_url, str_get_url);
	}
	if (str_send_url[0] == '\0') {
		strcpy(config.str_send_url, SEND_UPDATES_API_URL);
	} else {
		strcpy(config.str_send_url, str_send_url);
	}

	return config;
}

