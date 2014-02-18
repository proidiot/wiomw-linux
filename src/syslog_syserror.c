#include <config.h>
#include "syslog_syserror.h"
#include <syslog.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

#define MAX_ERROR_STRING_LENGTH BUFSIZ

void syslog_syserror(int priority, const char* format, ...)
{
	const int local_errno_copy = errno;
	char error_buffer[MAX_ERROR_STRING_LENGTH];
	va_list var_args;

	/* Get the extra args to be passed to syslog. */
	va_start(var_args, format);

	strncpy(error_buffer, format, MAX_ERROR_STRING_LENGTH);

	/* Add the separator. */
	strncpy(error_buffer + strlen(error_buffer), ": ", MAX_ERROR_STRING_LENGTH - strlen(error_buffer));

	/* Add the system error message. */
	strerror_r(
			local_errno_copy,
			error_buffer + strlen(error_buffer),
			MAX_ERROR_STRING_LENGTH - strlen(error_buffer));

	/* Write the error to syslog. */
	vsyslog(priority, error_buffer, var_args);

	/* Make sure the va_list stuff doesn't explode. */
	va_end(var_args);
}

