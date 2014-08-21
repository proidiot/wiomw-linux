# Copyright 2013, 2014 Who Is On My WiFi.
#
# This file is part of Who Is On My WiFi Linux.
#
# Who Is On My WiFi Linux is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# Who Is On My WiFi Linux is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# Who Is On My WiFi Linux.  If not, see <http://www.gnu.org/licenses/>.
#
# More information about Who Is On My WiFi Linux can be found at
# <http://www.whoisonmywifi.com/>.
#

sbin_PROGRAMS = wiomw-agent

wiomw_agent_SOURCES = main.c \
		       configuration.c \
		       configuration.h \
		       signal_handler.c \
		       signal_handler.h \
		       syslog_syserror.c \
		       syslog_syserror.h \
		       api.c \
		       api.h \
		       iface.c \
		       iface.h \
		       ifaddr.c \
		       ifaddr.h \
		       neighbour.c \
		       neighbour.h \
		       data_tracker.c \
		       data_tracker.h \
		       ip.c \
		       ip.h \
		       mnl_helpers.c \
		       mnl_helpers.h \
		       sockaddr_helpers.c \
		       sockaddr_helpers.h \
		       mac_ntop.c \
		       mac_ntop.h \
		       nl_listener.h \
		       nl_listener.c \
		       iptables_block.c \
		       block.h \
		       string_helpers.c \
		       string_helpers.h \
		       host_lookup.c \
		       host_lookup.h \
		       exp_backoff.c \
		       exp_backoff.h
AM_CFLAGS=${CURL_CFLAGS} ${PTHREAD_CFLAGS} ${LIBMNL_CFLAGS} -DSYSCONFDIR=\"${sysconfdir}\" --coverage
wiomw_agent_LDADD=${CURL_LIBS} ${PTHREAD_LIBS} ${LIBMNL_LIBS}

#install-exec-hook:
#	chown root $(sbindir)/wiomw-plugin
#	chmod u+s $(sbindir)/wiomw-plugin

