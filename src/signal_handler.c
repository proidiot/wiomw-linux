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

#include <config.h>
#include "signal_handler.h"
#include <syslog.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

volatile sig_atomic_t bool_stop_received;

void signal_callback(int signal)
{
	if (signal != SIGALRM) {
		syslog(LOG_NOTICE, "Caught signal %d: %s", signal, strsignal(signal));
		bool_stop_received = (1==1);
	}
}

void set_signal_handlers()
{
	struct sigaction struct_sigaction_ignore_handler;
	struct sigaction struct_sigaction_callback_handler;

	bool_stop_received = (1==0);

	struct_sigaction_ignore_handler.sa_handler = SIG_IGN;
	sigemptyset(&(struct_sigaction_ignore_handler.sa_mask));
	struct_sigaction_ignore_handler.sa_flags = SA_RESTART;

	struct_sigaction_callback_handler.sa_handler = &signal_callback;
	sigfillset(&(struct_sigaction_callback_handler.sa_mask));
	struct_sigaction_callback_handler.sa_flags = SA_RESTART;

	/* Ignore the signal that is sent when the calling terminal is closed. */
	sigaction(SIGHUP, &struct_sigaction_ignore_handler, NULL);

	/* Handle termination and alarm signals. */
	/*
	sigaction(SIGTERM, &struct_sigaction_callback_handler, NULL);
	sigaction(SIGINT, &struct_sigaction_callback_handler, NULL);
	*/
	sigaction(SIGALRM, &struct_sigaction_callback_handler, NULL);
}

int stop_signal_received()
{
	return bool_stop_received == (1==1);
}

bool full_sleep(unsigned int length)
{
	alarm(length);
	sigset_t sigset_emptyset;
	sigemptyset(&sigset_emptyset);
	sigsuspend(&sigset_emptyset);
	return !stop_signal_received();
}

bool any_nap(unsigned int nap_length, time_t nap_ceil) {
	time_t now = time(NULL);
	if (now >= nap_ceil) {
		return false;
	} else if (nap_ceil - now < nap_length) {
		return full_sleep(nap_ceil - now);
	} else {
		return full_sleep(nap_length);
	}
}

bool full_nap(unsigned int nap_length, time_t nap_ceil) {
	time_t now = time(NULL);
	if (now >= nap_ceil) {
		return false;
	} else if (nap_ceil - now < nap_length) {
		return false;
	} else {
		return full_sleep(nap_length);
	}
}

