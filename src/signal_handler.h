#ifndef _WIOMW_SIGNAL_HANDLER_H_
#define _WIOMW_SIGNAL_HANDLER_H_

void set_signal_handlers();

int stop_signal_received();

void sleep_until_signalled();

#endif

