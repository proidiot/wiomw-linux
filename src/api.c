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

#include <config.h>
#include <syslog.h>
#include "syslog_syserror.h"
#include "api.h"
#include "configuration.h"
#include "neighbours.h"
#include "block.h"
#include "string_helpers.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <ctype.h>

typedef struct holder_t_struct {
	size_t size_offset;
	char* str_data;
} * holder_t;

char* get_unique_agent_key()
{
	return "4";
}

size_t curl_cb_process_buffer(void* data_buffer, size_t unit_size, size_t unit_count, void* passed_holder_t_data)
{
	size_t buffer_count = 0;
	holder_t holder_t_data;

	if (passed_holder_t_data == NULL) {
		syslog(LOG_CRIT, "Internal error within cURL callback");
		exit(EX_SOFTWARE);
	}
	holder_t_data = (holder_t)passed_holder_t_data;

	if (holder_t_data->size_offset == 0) {
		holder_t_data->str_data = (char*)malloc((unit_size * unit_count) + 1);
	} else {
		holder_t_data->str_data = (char*)realloc(
				holder_t_data->str_data,
				holder_t_data->size_offset + (unit_size * unit_count) + 1);
	}
	if (holder_t_data->str_data == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to allocate memory");
		exit(EX_OSERR);
	}

	for (buffer_count = 0; buffer_count < unit_count; buffer_count++) {
		memcpy(
				holder_t_data->str_data + holder_t_data->size_offset,
				(char*)data_buffer + (buffer_count * unit_size),
				unit_size);
		holder_t_data->size_offset += unit_size;
	}
	holder_t_data->str_data[holder_t_data->size_offset] = '\0';

	return buffer_count * unit_size;
}

void wiomw_login(config_t* config)
{
	char str_error_buffer[CURL_ERROR_SIZE];
	holder_t holder_t_data;
	FILE* fd;
	long fd_size;
	bool retry = false;
	unsigned int tries = 1;

	if (config == NULL) {
		syslog(LOG_CRIT, "Internal error during login (empty config)");
		exit(EX_SOFTWARE);
	}

	holder_t_data = (holder_t)malloc(sizeof(struct holder_t_struct));
	if (holder_t_data == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to allocate memory");
		exit(EX_OSERR);
	}

	if ((fd = tmpfile()) == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to create temproary file");
		exit(EX_OSERR);
	}

	fprintf(fd, "{\"username\":\"%s\",\"password\":\"%s\",\"agentkey\":\"%s\"}", config->username, config->passhash, config->agentkey);

	fseek(fd, 0, SEEK_END);
	fd_size = ftell(fd);

	do {
		CURL* curl_handle = curl_easy_init();

		retry = false;

		rewind(fd);

		memset(holder_t_data, 0, sizeof(struct holder_t_struct));
	
		curl_easy_setopt(curl_handle, CURLOPT_URL, config->login_url);
		curl_easy_setopt(curl_handle, CURLOPT_CAINFO, config->capath);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, &curl_cb_process_buffer);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, holder_t_data);
		curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, str_error_buffer);
		curl_easy_setopt(curl_handle, CURLOPT_POST, 1);
		curl_easy_setopt(curl_handle, CURLOPT_READDATA, fd);
		curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, fd_size);
	
		if (curl_easy_perform(curl_handle) == 0) {
			size_t size_data_length;
			if (holder_t_data->size_offset == 0) {
				syslog(LOG_ALERT, "Server response to login was empty (potential security breach)");
				exit(EX_PROTOCOL);
			}
			
			size_data_length = strlen(holder_t_data->str_data);
			if (size_data_length > CONFIG_OPTION_SESSION_ID_LENGTH) {
				syslog(LOG_CRIT, "Session ID sent by server is too big to store");
				exit(EX_PROTOCOL);
			} else {
				int i = 0;
				config->session_id = string_chomp_copy(holder_t_data->str_data);
				for (i = 0; config->session_id[i] != '\0'; i++) {
					if (!isalnum(config->session_id[i])) {
						syslog(LOG_ERR, "Received an invalid session ID (possibly bad username or password hash)");
						exit(EX_DATAERR);
					}
				}
				if (i != 40) {
					syslog(LOG_ERR, "Received an invalid session ID (possibly bad username or password hash)");
					exit(EX_DATAERR);
				}
				config->next_session_request = time(NULL) + CONFIG_OPTION_SESSION_LENGTH;
			}
		} else {
			syslog(LOG_ERR, "Login attempt %u failed: %s", tries, str_error_buffer);
			retry = true;
		}
	
		curl_easy_cleanup(curl_handle);
		if (holder_t_data->str_data != NULL) {
			free(holder_t_data->str_data);
		}
	} while (retry && full_sleep(trunc_exp_backoff(tries++, CONFIG_OPTION_BACKOFF_CEILING)));

	free(holder_t_data);
}

void send_config(config_t* config)
{
	char str_error_buffer[CURL_ERROR_SIZE];
	holder_t holder_t_data;
	FILE* fd;
	long fd_size;
	bool retry = false;
	unsigned int tries = 1;

	if (config == NULL) {
		syslog(LOG_CRIT, "Internal error during version announcement (empty config)");
		exit(EX_SOFTWARE);
	}

	holder_t_data = (holder_t)malloc(sizeof(struct holder_t_struct));
	if (holder_t_data == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to allocate memory");
		exit(EX_OSERR);
	}

	if ((fd = tmpfile()) == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to create temproary file");
		exit(EX_OSERR);
	}

	fprintf(fd, "[%s, {\"frequency\":\"%d\",\"agent_version\":\"%s_%s_%s\",\"apiversion\":\"v100\",\"agentdetail\":\"%s, agent type %s, calling REST interface\", \"agenttime\":\"%ld\"}]", config->session_id, CONFIG_OPTION_SYNC_BLOCK_FREQUENCY, CONFIG_OPTION_AGENT_TYPE, PACKAGE_NAME, PACKAGE_VERSION, PACKAGE_STRING, CONFIG_OPTION_AGENT_TYPE, time(NULL));

	fseek(fd, 0, SEEK_END);
	fd_size = ftell(fd);

	do {
		CURL* curl_handle = curl_easy_init();

		retry = false;

		rewind(fd);
	
		memset(holder_t_data, 0, sizeof(struct holder_t_struct));

		curl_easy_setopt(curl_handle, CURLOPT_URL, config->config_agent_url);
		curl_easy_setopt(curl_handle, CURLOPT_CAINFO, config->capath);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, &curl_cb_process_buffer);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, holder_t_data);
		curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, str_error_buffer);
		curl_easy_setopt(curl_handle, CURLOPT_POST, 1);
		curl_easy_setopt(curl_handle, CURLOPT_READDATA, fd);
		curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, fd_size);
	
		if (curl_easy_perform(curl_handle) == 0) {
			if (holder_t_data->size_offset == 0) {
				syslog(LOG_ERR, "Server response to version announcement was empty");
				exit(EX_PROTOCOL);
			}
		} else {
			syslog(LOG_ERR, "Version announcement attempt %u failed: %s", tries, str_error_buffer);
			retry = true;
		}
	
		curl_easy_cleanup(curl_handle);
		if (holder_t_data->str_data != NULL) {
			free(holder_t_data->str_data);
		}
	} while (retry && full_nap(trunc_exp_backoff(tries++, CONFIG_OPTION_BACKOFF_CEILING), config->next_session_request));

	free(holder_t_data);
}

void sync_block(config_t* config)
{
	char str_error_buffer[CURL_ERROR_SIZE];
	holder_t holder_t_data;
	FILE* fd;
	long fd_size;
	bool retry = false;
	unsigned int tries = 1;

	if (config == NULL) {
		syslog(LOG_CRIT, "Internal error during device blocking setup (empty config)");
		exit(EX_SOFTWARE);
	} else if (!config->allow_blocking) {
		return;
	}

	holder_t_data = (holder_t)malloc(sizeof(struct holder_t_struct));
	if (holder_t_data == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to allocate memory");
		exit(EX_OSERR);
	}

	if ((fd = tmpfile()) == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to create temproary file");
		exit(EX_OSERR);
	}

	fprintf(fd, "[\"%s\"]", config->session_id);

	fseek(fd, 0, SEEK_END);
	fd_size = ftell(fd);

	do {
		CURL* curl_handle = curl_easy_init();
	
		retry = false;
	
		rewind(fd);
	
		memset(holder_t_data, 0, sizeof(struct holder_t_struct));
	
		curl_easy_setopt(curl_handle, CURLOPT_URL, config->sync_block_url);
		curl_easy_setopt(curl_handle, CURLOPT_CAINFO, config->capath);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, &curl_cb_process_buffer);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, holder_t_data);
		curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, str_error_buffer);
		curl_easy_setopt(curl_handle, CURLOPT_POST, 1);
		curl_easy_setopt(curl_handle, CURLOPT_READDATA, fd);
		curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, fd_size);
	
		if (curl_easy_perform(curl_handle) == 0) {
			if (holder_t_data->size_offset == 0) {
				syslog(LOG_ALERT, "Server response to device blocking setup was empty (potential security breach)");
				exit(EX_PROTOCOL);
			}
			
			apply_blocks(holder_t_data->str_data);
		} else {
			syslog(LOG_ERR, "Device blocking setup attempt %u failed: %s", tries, str_error_buffer);
			retry = true;
		}
	
		curl_easy_cleanup(curl_handle);
		if (holder_t_data->str_data != NULL) {
			free(holder_t_data->str_data);
		}
	} while (retry && full_nap(trunc_exp_backoff(tries++, CONFIG_OPTION_BACKOFF_CEILING), config->next_session_request));

	free(holder_t_data);
}

void send_subnet_and_devices(config_t* config)
{
	char str_error_buffer[CURL_ERROR_SIZE];
	holder_t holder_t_data;
	FILE* subnet_fd;
	FILE* devices_fd;
	long subnet_fd_size;
	long devices_fd_size;
	bool retry = false;
	unsigned int tries = 1;

	if (config == NULL) {
		syslog(LOG_CRIT, "Internal error during report (empty config)");
		exit(EX_SOFTWARE);
	}

	holder_t_data = (holder_t)malloc(sizeof(struct holder_t_struct));
	if (holder_t_data == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to allocate memory");
		exit(EX_OSERR);
	}

	if (((subnet_fd = tmpfile()) == NULL) || ((devices_fd = tmpfile()) == NULL)) {
		syslog_syserror(LOG_EMERG, "Unable to create temproary file");
		exit(EX_OSERR);
	}
	print_neighbours(config, subnet_fd, devices_fd);
	fseek(subnet_fd, 0, SEEK_END);
	subnet_fd_size = ftell(subnet_fd);
	fseek(devices_fd, 0, SEEK_END);
	devices_fd_size = ftell(devices_fd);

	do {
		CURL* curl_handle;
	
		retry = false;
	
		rewind(subnet_fd);
	
		memset(holder_t_data, 0, sizeof(struct holder_t_struct));
	
		curl_handle = curl_easy_init();
		curl_easy_setopt(curl_handle, CURLOPT_URL, config->config_subnet_url);
		curl_easy_setopt(curl_handle, CURLOPT_CAINFO, config->capath);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, &curl_cb_process_buffer);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, holder_t_data);
		curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, str_error_buffer);
		curl_easy_setopt(curl_handle, CURLOPT_POST, 1);
		curl_easy_setopt(curl_handle, CURLOPT_READDATA, subnet_fd);
		curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, subnet_fd_size);
	
		if (curl_easy_perform(curl_handle) == 0) {
			if (holder_t_data->size_offset == 0) {
				syslog(LOG_ERR, "Server response to network layout report was empty");
				exit(EX_PROTOCOL);
			}
		} else {
			syslog(LOG_ERR, "Network layout report attempt %u failed: %s", tries, str_error_buffer);
			retry = true;
		}
	
		curl_easy_cleanup(curl_handle);
		if (holder_t_data->str_data != NULL) {
			free(holder_t_data->str_data);
		}
	} while (retry && full_nap(trunc_exp_backoff(tries++, CONFIG_OPTION_BACKOFF_CEILING), config->next_session_request));

	if (stop_signal_received() || session_has_expired(*config)) {
		free(holder_t_data);
		return;
	}

	tries = 1;
	retry = false;

	do {
		CURL* curl_handle;
	
		retry = false;
	
		rewind(devices_fd);

		memset(holder_t_data, 0, sizeof(struct holder_t_struct));
	
		curl_handle = curl_easy_init();
		curl_easy_setopt(curl_handle, CURLOPT_URL, config->send_devices_url);
		curl_easy_setopt(curl_handle, CURLOPT_CAINFO, config->capath);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, &curl_cb_process_buffer);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, holder_t_data);
		curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, str_error_buffer);
		curl_easy_setopt(curl_handle, CURLOPT_POST, 1);
		curl_easy_setopt(curl_handle, CURLOPT_READDATA, devices_fd);
		curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, devices_fd_size);
	
		if (curl_easy_perform(curl_handle) == 0) {
			if (holder_t_data->size_offset == 0) {
				syslog(LOG_ALERT, "Server response to network device report was empty (potential security breach)");
				exit(EX_PROTOCOL);
			}
		} else {
			syslog(LOG_ERR, "Network device report attempt %u failed: %s", tries, str_error_buffer);
			retry = true;
		}
		
		curl_easy_cleanup(curl_handle);
		if (holder_t_data->str_data != NULL) {
			free(holder_t_data->str_data);
		}
	} while (retry && full_nap(trunc_exp_backoff(tries++, CONFIG_OPTION_BACKOFF_CEILING), config->next_session_request));

	free(holder_t_data);
}

