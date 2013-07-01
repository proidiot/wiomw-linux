#include <config.h>
#include "print_error.h"
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

#define UNIVERSAL_ERROR_STRING_PREFIX "WIOMW Plugin: "
#define DEBUG_ERROR_STRING_PREFIX UNIVERSAL_ERROR_STRING_PREFIX "DEBUG: "
#define MAX_ERROR_STRING_LENGTH BUFSIZ

#define ENABLE_DEBUG 1

void print_syserror(const char* const str_format, ...)
{
	const int int_local_errno_copy = errno;
	char str_error_buffer[MAX_ERROR_STRING_LENGTH];
	va_list va_list_printf_args;

	/* Get the extra args to be passed to printf. */
	va_start(va_list_printf_args, str_format);

	/* Prepend the universal error string. */
	strcpy(str_error_buffer, UNIVERSAL_ERROR_STRING_PREFIX);

	/* Add the printf-style string. */
	vsnprintf(
			str_error_buffer + strlen(str_error_buffer),
			MAX_ERROR_STRING_LENGTH - strlen(str_error_buffer),
			str_format,
			va_list_printf_args);

	/* Add the separator. */
	strncpy(str_error_buffer + strlen(str_error_buffer), ": ", MAX_ERROR_STRING_LENGTH - strlen(str_error_buffer));

	/* Add the system error message. */
	strerror_r(
			int_local_errno_copy,
			str_error_buffer + strlen(str_error_buffer),
			MAX_ERROR_STRING_LENGTH - strlen(str_error_buffer));

	/* Write the error to stderr. */
	fprintf(stderr, "%s\n", str_error_buffer);

	/* Make sure the va_list stuff doesn't explode. */
	va_end(va_list_printf_args);
}

void print_error(const char* const str_format, ...)
{
	char str_error_buffer[MAX_ERROR_STRING_LENGTH];
	va_list va_list_printf_args;

	/* Get the extra args to be passed to printf. */
	va_start(va_list_printf_args, str_format);

	/* Prepend the universal error string. */
	strcpy(str_error_buffer, UNIVERSAL_ERROR_STRING_PREFIX);

	/* Add the printf-style string. */
	vsnprintf(
			str_error_buffer + strlen(str_error_buffer),
			MAX_ERROR_STRING_LENGTH - strlen(str_error_buffer),
			str_format,
			va_list_printf_args);

	/* Write the error to stderr. */
	fprintf(stderr, "%s\n", str_error_buffer);

	/* Make sure the va_list stuff doesn't explode. */
	va_end(va_list_printf_args);
}

void print_debug(const char* const str_format, ...)
{
	if (ENABLE_DEBUG) {
		char str_error_buffer[MAX_ERROR_STRING_LENGTH];
		va_list va_list_printf_args;

		/* Get the extra args to be passed to printf. */
		va_start(va_list_printf_args, str_format);

		/* Prepend the universal error string. */
		strcpy(str_error_buffer, UNIVERSAL_ERROR_STRING_PREFIX);

		/* Add the printf-style string. */
		vsnprintf(
				str_error_buffer + strlen(str_error_buffer),
				MAX_ERROR_STRING_LENGTH - strlen(str_error_buffer),
				str_format,
				va_list_printf_args);

		/* Write the error to stderr. */
		fprintf(stderr, "%s\n", str_error_buffer);

		/* Make sure the va_list stuff doesn't explode. */
		va_end(va_list_printf_args);
	}
}

