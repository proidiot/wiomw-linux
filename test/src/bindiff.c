#include <config.h>

#include <stdio.h>
#include <stdlib.h>

#include "../../src/string_helpers.h"

char* bindiff(const unsigned char* expected, const unsigned char* actual, const size_t length, unsigned char cols)
{
	size_t temp = 1;
	size_t offset = 0;
	unsigned char digits = 1;
	unsigned char bytes_per_line = 1;
	char* result = NULL;
	size_t reslen = 0;
	char* tres = NULL;
	size_t tlen = 0;
	for (temp = 10; temp <= length; temp *= 10) {
		digits++;
	}
	if (cols == 0) {
		bytes_per_line = 4;
		cols = digits + 4 + (bytes_per_line * 4);
	} else if ((digits + 8) > cols) {
		return NULL;
	} else {
		bytes_per_line = (cols - digits - 4) / 4;
	}

	reslen = (cols + 1) * (3 + (length / bytes_per_line));
	result = (char*)malloc(reslen);
	tres = result;
	tlen = reslen;

	if (digits == 1) {
		astpnprintf(&tres, &tlen, "o");
	} else if (digits == 2) {
		astpnprintf(&tres, &tlen, "of");
	} else if (digits < 7) {
		astpnprintf(&tres, &tlen, "%.*s", digits, "ofs");
	} else {
		astpnprintf(&tres, &tlen, "%.*s", digits, "offset");
	}

	astpnprintf(&tres, &tlen, "  ");

	if (bytes_per_line == 1) {
		astpnprintf(&tres, &tlen, "ex  ac\n");
	} else if (bytes_per_line < 4) {
		astpnprintf(&tres, &tlen, "%.*s  %.*s\n", bytes_per_line*2, "exp", bytes_per_line*2, "act");
	} else {
		astpnprintf(&tres, &tlen, "%.*s  %.*s\n", bytes_per_line*2, "expected", bytes_per_line*2, "actual");
	}

	for (temp = 0; temp < cols; temp++) {
		astpnprintf(&tres, &tlen, "-");
	}
	astpnprintf(&tres, &tlen, "\n");

	for (offset = 0; offset < length; offset += bytes_per_line) {
		astpnprintf(&tres, &tlen, "%0*zu  ", digits, offset);
		if (length < (offset + bytes_per_line)) {
			for (temp = offset; temp < length; temp++) {
				astpnprintf(&tres, &tlen, "%02X", expected[temp]);
			}
			for (temp = bytes_per_line - (length - offset); temp > 0; temp--) {
				astpnprintf(&tres, &tlen, "  ");
			}
			astpnprintf(&tres, &tlen, "  ");
			for (temp = offset; temp < length; temp++) {
				astpnprintf(&tres, &tlen, "%02X", actual[temp]);
			}
			for (temp = bytes_per_line - (length - offset); temp > 0; temp--) {
				astpnprintf(&tres, &tlen, "  ");
			}
		} else {
			for (temp = 0; temp < bytes_per_line; temp++) {
				astpnprintf(&tres, &tlen, "%02X", expected[offset + temp]);
			}
			astpnprintf(&tres, &tlen, "  ");
			for (temp = 0; temp < bytes_per_line; temp++) {
				astpnprintf(&tres, &tlen, "%02X", actual[offset + temp]);
			}
		}
		astpnprintf(&tres, &tlen, "\n");
	}

	return result;
}

