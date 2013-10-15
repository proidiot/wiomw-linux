#ifndef _WIOMW_PRINT_ERROR_H_
#define _WIOMW_PRINT_ERROR_H_

void print_syserror(const char* const str_format, ...);
void print_error(const char* const str_format, ...);
void print_debug(const char* const str_format, ...);

#define WHERE_AM_I() print_debug("HERE_I_AM: %s:%d", __FILE__, __LINE__)

#endif
