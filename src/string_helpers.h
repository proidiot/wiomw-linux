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

#ifndef _WIOMW_STRING_HELPERS_H_
#define _WIOMW_STRING_HELPERS_H_

#include <stddef.h>

char* string_chomp_copy(char* source);

int parse_uint(char* source);

int parse_bool(char* source);

/* In lieu of a working, POSIX-compliant strnlen in uClibc's string.h... */
size_t safe_string_length(const char* s, size_t maxlen);

char* regex_escape_ifname(char* ifname);

#endif
