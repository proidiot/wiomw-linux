#include <config.h>
#include "signal_handler.h"
#include "print_error.h"
#include <signal.h>
#include <stdlib.h>
#include <string.h>

volatile sig_atomic_t bool_stop_received;

void signal_callback(int signal)
{
	if (signal != SIGALRM) {
		print_error("Caught signal %d: %s", signal);
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
	sigaction(SIGTERM, &struct_sigaction_callback_handler, NULL);
	sigaction(SIGINT, &struct_sigaction_callback_handler, NULL);
	sigaction(SIGALRM, &struct_sigaction_callback_handler, NULL);

	/* Compile-time decision as to whether SIGQUIT should be handled (maybe to obfuscate the core dump?). */
	if (SHOULD_HANDLE_SIGQUIT) {
		sigaction(SIGQUIT, &struct_sigaction_callback_handler, NULL);
	}
}

int stop_signal_received()
{
	return bool_stop_received == (1==1);
}

void sleep_until_signalled()
{
	sigset_t sigset_emptyset;
	sigemptyset(&sigset_emptyset);
	sigsuspend(&sigset_emptyset);
}


