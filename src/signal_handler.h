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

#ifndef _WIOMW_SIGNAL_HANDLER_H_
#define _WIOMW_SIGNAL_HANDLER_H_

#include <stdbool.h>
#include <time.h>

void set_signal_handlers();

int stop_signal_received();

bool full_sleep(unsigned int length);
bool any_nap(unsigned int nap_length, time_t nap_ceil);
bool full_nap(unsigned int nap_length, time_t nap_ceil);

#endif

