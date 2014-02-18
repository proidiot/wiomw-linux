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
		       neighbours.c \
		       neighbours.h \
		       sockaddr_helpers.c \
		       sockaddr_helpers.h \
		       mac_ntop.c \
		       mac_ntop.h \
		       iptables_block.c \
		       block.h \
		       string_helpers.c \
		       string_helpers.h \
		       host_lookup.c \
		       host_lookup.h
AM_CFLAGS=${CURL_CFLAGS} ${PTHREAD_CFLAGS} ${LIBMNL_CFLAGS} -DSYSCONFDIR=\"${sysconfdir}\"
wiomw_agent_LDADD=${CURL_LIBS} ${PTHREAD_LIBS} ${LIBMNL_LIBS}

#install-exec-hook:
#	chown root $(sbindir)/wiomw-plugin
#	chmod u+s $(sbindir)/wiomw-plugin

