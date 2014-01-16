#ifndef _WIOMW_STRING_HELPERS_H_
#define _WIOMW_STRING_HELPERS_H_

char* string_chomp_copy(char* source);

int parse_uint(char* source);

int parse_bool(char* source);

/* In lieu of a working, POSIX-compliant strnlen in uClibc's string.h... */
size_t safe_string_length(const char* s, size_t maxlen);

#endif
