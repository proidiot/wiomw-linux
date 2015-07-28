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

#include "string_helpers.h"

#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <ctype.h>
#include "syslog_syserror.h"

char* string_chomp_copy(char* source)
{
	char* dest = NULL;
	size_t i = 0;
	size_t len = 0;

	while (source[i] == ' ' || source[i] == '\t') {
		i++;
	}

	len = strlen(source + i);

	while (len != 0 && (source[i + len - 1] == '\n' || source[i + len - 1] == ' ' || source[i + len - 1] == '\t')) {
		len--;
	}

	if (len == 0) {
		return NULL;
	}


	dest = (char*)malloc(len + 1);
	if (dest == NULL) {
		syslog_syserror(LOG_EMERG, "Unable to allocate memory");
		exit(EX_OSERR);
	}

	strncpy(dest, source + i, len);
	dest[len] = '\0';

	return dest;
}

int parse_uint(char* source)
{
	int result = -1;
	size_t i = 0;

	while (source[i] == ' ' || source[i] == '\t') {
		i++;
	}

	if (source[i] < '0' || source[i] > '9') {
		return -1;
	} else {
		result = source[i] - '0';
	}

	while (source[i] >= '0' && source[i] <= '9') {
		result *= 10;
		result += source[i] - '0';
	}

	if (source[i] != ' ' && source[i] != '\t' && source[i] != '\n' && source[i] != '\0') {
		return -1;
	} else {
		return result;
	}
}

int parse_bool(char* source)
{
	size_t i = 0;

	while (source[i] == ' ' || source[i] == '\t') {
		i++;
	}

	if (source[i] == 't') {
		i++;

		if (source[i] == 'r' && source[i+1] == 'u' && source[i+2] =='e') {
			i += 3;
		}

		while (source[i] == ' ' || source[i] == '\t') {
			i++;
		}

		if (source[i] == '\n' || source[i] == '\0') {
			return 1;
		} else {
			return -1;
		}
	} else if (source[i] == 'T') {
		i++;

		if (source[i] == 'r' && source[i+1] == 'u' && source[i+2] =='e') {
			i += 3;
		} else if (source[i] == 'R' && source[i+1] == 'U' && source[i+2] =='E') {
			i += 3;
		}

		while (source[i] == ' ' || source[i] == '\t') {
			i++;
		}

		if (source[i] == '\n' || source[i] == '\0') {
			return 1;
		} else {
			return -1;
		}
	} else if (source[i] == 'y') {
		i++;

		if (source[i] == 'e' && source[i+1] == 's') {
			i += 2;
		}

		while (source[i] == ' ' || source[i] == '\t') {
			i++;
		}

		if (source[i] == '\n' || source[i] == '\0') {
			return 1;
		} else {
			return -1;
		}
	} else if (source[i] == 'Y') {
		i++;

		if (source[i] == 'e' && source[i+1] == 's') {
			i += 2;
		} else if (source[i] == 'E' && source[i+1] == 'S') {
			i += 2;
		}

		while (source[i] == ' ' || source[i] == '\t') {
			i++;
		}

		if (source[i] == '\n' || source[i] == '\0') {
			return 1;
		} else {
			return -1;
		}
	} else if (source[i] == '1') {
		i++;

		while (source[i] == ' ' || source[i] == '\t') {
			i++;
		}

		if (source[i] == '\n' || source[i] == '\0') {
			return 1;
		} else {
			return -1;
		}
	} else if (source[i] == 'f') {
		i++;

		if (source[i] == 'a' && source[i+1] == 'l' && source[i+2] =='s' && source[i+3] == 'e') {
			i += 4;
		}

		while (source[i] == ' ' || source[i] == '\t') {
			i++;
		}

		if (source[i] == '\n' || source[i] == '\0') {
			return 0;
		} else {
			return -1;
		}
	} else if (source[i] == 'F') {
		i++;

		if (source[i] == 'a' && source[i+1] == 'l' && source[i+2] =='s' && source[i+3] == 'e') {
			i += 4;
		} else if (source[i] == 'A' && source[i+1] == 'L' && source[i+2] =='S' && source[i+3] == 'E') {
			i += 4;
		}

		while (source[i] == ' ' || source[i] == '\t') {
			i++;
		}

		if (source[i] == '\n' || source[i] == '\0') {
			return 0;
		} else {
			return -1;
		}
	} else if (source[i] == 'n') {
		i++;

		if (source[i] == 'o') {
			i++;
		}

		while (source[i] == ' ' || source[i] == '\t') {
			i++;
		}

		if (source[i] == '\n' || source[i] == '\0') {
			return 0;
		} else {
			return -1;
		}
	} else if (source[i] == 'N') {
		i++;

		if (source[i] == 'o' || source[i] == 'O') {
			i++;
		}

		while (source[i] == ' ' || source[i] == '\t') {
			i++;
		}

		if (source[i] == '\n' || source[i] == '\0') {
			return 0;
		} else {
			return -1;
		}
	} else if (source[i] == '0') {
		i++;

		while (source[i] == ' ' || source[i] == '\t') {
			i++;
		}

		if (source[i] == '\n' || source[i] == '\0') {
			return 0;
		} else {
			return -1;
		}
	} else {
		return -1;
	}

}

/* In lieu of a working, POSIX-compliant strnlen in uClibc's string.h... */
size_t safe_string_length(const char* s, size_t maxlen)
{
	if (s == NULL) {
		return 0;
	} else {
		register size_t offset = 0;
		for (offset = 0; offset < maxlen; offset++) {
			if (s[offset] == '\0') {
				return offset;
			}
		}
		return maxlen;
	}
}

char* regex_escape_ifname(char* ifname)
{
	size_t periods = 0;
	size_t i = 0;
	char c = '\0';
	while ((c = ifname[i++]) != '\0') {
		if (c == '.') {
			periods++;
		} else if (!isalnum(c)) {
			syslog(LOG_CRIT, "Non-alphanumeric characters other than period aren't supposed to be part of a network interface name");
			exit(EX_CONFIG);
		}
	}
	if (periods > 0) {
		size_t j = 0;
		char* result = (char*)malloc(i + periods + 1);
		if (result == NULL) {
			syslog_syserror(LOG_EMERG, "Unable to allocate memory");
			exit(EX_OSERR);
		}
		i = 0;
		while((c = ifname[i++]) != '\0') {
			if (c == '.') {
				result[j++] = '\\';
			}
			result[j++] = c;
		}
		result[j] = '\0';
		return result;
	} else {
		return ifname;
	}
}

