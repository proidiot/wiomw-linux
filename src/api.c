#include <config.h>
#include "print_error.h"
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
		print_error("Unable to determine where to store the data from the server");
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
		print_syserror("Unable to allocate memory to store additional data from the server");
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
	CURL* curl_handle;
	FILE* fd;
	long fd_size;

	if (config == NULL) {
		print_error("Unexpected empty configuration");
		exit(EX_SOFTWARE);
	}

	holder_t_data = (holder_t)malloc(sizeof(struct holder_t_struct));
	if (holder_t_data == NULL) {
		print_syserror("Unable to allocate memory to store the data from the server");
		exit(EX_OSERR);
	}
	holder_t_data->size_offset = 0;
	holder_t_data->str_data = NULL;

	if ((fd = tmpfile()) == NULL) {
		print_syserror("Unable to open the temproary file to store data to send to the server");
	}

	fprintf(fd, "{\"username\":\"%s\",\"password\":\"%s\",\"agentkey\":\"%s\"}", config->username, config->passhash, config->agentkey);

	fseek(fd, 0, SEEK_END);
	fd_size = ftell(fd);
	rewind(fd);

	curl_handle = curl_easy_init();
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
			print_error("Did not receive data from the server");
			exit(EX_PROTOCOL);
		}
		
		size_data_length = strlen(holder_t_data->str_data);
		if (size_data_length > CONFIG_OPTION_SESSION_ID_LENGTH) {
			print_error("Session ID received was larger than %d bytes", CONFIG_OPTION_SESSION_ID_LENGTH);
			exit(EX_PROTOCOL);
		} else {
			int i = 0;
			config->session_id = string_chomp_copy(holder_t_data->str_data);
			for (i = 0; config->session_id[i] != '\0'; i++) {
				if (!isalnum(config->session_id[i])) {
					print_error("Invalid session ID");
					exit(EX_DATAERR);
				}
			}
			if (i != 40) {
				print_error("Invalid session ID");
				exit(EX_DATAERR);
			}
		}
	} else {
		print_error("Login failed: %s", str_error_buffer);
		exit(EX_UNAVAILABLE);
	}

	curl_easy_cleanup(curl_handle);
	free(holder_t_data);
}

void send_config(config_t* config)
{
	char str_error_buffer[CURL_ERROR_SIZE];
	holder_t holder_t_data;
	CURL* curl_handle;
	FILE* fd;
	long fd_size;

	if (config == NULL) {
		print_error("Unexpected empty configuration");
		exit(EX_SOFTWARE);
	}

	holder_t_data = (holder_t)malloc(sizeof(struct holder_t_struct));
	if (holder_t_data == NULL) {
		print_syserror("Unable to allocate memory to store the data from the server");
		exit(EX_OSERR);
	}
	holder_t_data->size_offset = 0;
	holder_t_data->str_data = NULL;

	if ((fd = tmpfile()) == NULL) {
		print_syserror("Unable to open the temproary file to store data to send to the server");
	}

	fprintf(fd, "[%s, {\"frequency\":\"%d\",\"agent_version\":\"%s_%s_%s\",\"apiversion\":\"v100\",\"agentdetail\":\"%s, agent type %s, calling REST interface\", \"agenttime\":\"%ld\"}]", config->session_id, CONFIG_OPTION_SYNC_BLOCK_FREQUENCY, CONFIG_OPTION_AGENT_TYPE, PACKAGE_NAME, PACKAGE_VERSION, PACKAGE_STRING, CONFIG_OPTION_AGENT_TYPE, time(NULL));

	fseek(fd, 0, SEEK_END);
	fd_size = ftell(fd);
	rewind(fd);

	curl_handle = curl_easy_init();
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
			print_error("Did not receive data from the server");
			exit(EX_PROTOCOL);
		}
	} else {
		print_error("Send configuration failed: %s", str_error_buffer);
		exit(EX_UNAVAILABLE);
	}

	curl_easy_cleanup(curl_handle);
	free(holder_t_data);
}

void sync_block(config_t* config)
{
	char str_error_buffer[CURL_ERROR_SIZE];
	holder_t holder_t_data;
	CURL* curl_handle;
	FILE* fd;
	long fd_size;

	if (config == NULL) {
		print_error("Unexpected empty configuration");
		exit(EX_SOFTWARE);
	} else if (!config->allow_blocking) {
		return;
	}

	holder_t_data = (holder_t)malloc(sizeof(struct holder_t_struct));
	if (holder_t_data == NULL) {
		print_syserror("Unable to allocate memory to store the data from the server");
		exit(EX_OSERR);
	}
	holder_t_data->size_offset = 0;
	holder_t_data->str_data = NULL;

	if ((fd = tmpfile()) == NULL) {
		print_syserror("Unable to open the temproary file to store data to send to the server");
	}

	fprintf(fd, "[\"%s\"]", config->session_id);

	fseek(fd, 0, SEEK_END);
	fd_size = ftell(fd);
	rewind(fd);

	curl_handle = curl_easy_init();
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
			print_error("Did not receive data from the server");
			exit(EX_PROTOCOL);
		}
		
		apply_blocks(holder_t_data->str_data);
	} else {
		print_error("Get updates failed: %s", str_error_buffer);
		exit(EX_UNAVAILABLE);
	}

	curl_easy_cleanup(curl_handle);
	free(holder_t_data);
}

void send_devices(config_t* config)
{
	char str_error_buffer[CURL_ERROR_SIZE];
	holder_t holder_t_data;
	CURL* curl_handle;
	FILE* fd;
	long fd_size;

	if (config == NULL) {
		print_error("Unexpected empty configuration");
		exit(EX_SOFTWARE);
	}

	holder_t_data = (holder_t)malloc(sizeof(struct holder_t_struct));
	if (holder_t_data == NULL) {
		print_syserror("Unable to allocate memory to store the data from the server");
		exit(EX_OSERR);
	}
	holder_t_data->size_offset = 0;
	holder_t_data->str_data = NULL;

	if ((fd = tmpfile()) == NULL) {
		print_syserror("Unable to open the temproary file to store data to send to the server");
	}
	print_neighbours(config, fd);
	fseek(fd, 0, SEEK_END);
	fd_size = ftell(fd);
	rewind(fd);

	curl_handle = curl_easy_init();
	curl_easy_setopt(curl_handle, CURLOPT_URL, config->send_devices_url);
	curl_easy_setopt(curl_handle, CURLOPT_CAINFO, config->capath);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, &curl_cb_process_buffer);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, holder_t_data);
	curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, str_error_buffer);
	curl_easy_setopt(curl_handle, CURLOPT_POST, 1);
	curl_easy_setopt(curl_handle, CURLOPT_READDATA, fd);
	curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, fd_size);

	if (curl_easy_perform(curl_handle) == 0) {
		if (holder_t_data->size_offset == 0) {
			print_error("Did not receive data from the server");
			exit(EX_PROTOCOL);
		}
	} else {
		print_error("Send devices failed: %s", str_error_buffer);
		exit(EX_UNAVAILABLE);
	}

	curl_easy_cleanup(curl_handle);
	free(holder_t_data);
}

