bin_PROGRAMS = wiomw-plugin

wiomw_plugin_SOURCES = main.c \
		       configuration.c \
		       configuration.h.in \
		       signal_handler.c \
		       signal_handler.h \
		       print_error.c \
		       print_error.h \
		       api.c \
		       api.h \
		       neighbours.c \
		       neighbours.h \
		       sockaddr_helpers.c \
		       sockaddr_helpers.h \
		       mac_ntop.c \
		       mac_ntop.h
AM_CFLAGS=${CURL_CFLAGS} ${PTHREAD_CFLAGS} ${LIBMNL_CFLAGS} -DSYSCONFDIR=\"${sysconfdir}\"
#AM_CFLAGS=${CURL_CFLAGS} ${PTHREAD_CFLAGS} -isystem /usr/include/libnl3 -DSYSCONFDIR=\"${sysconfdir}\"
wiomw_plugin_LDADD=${CURL_LIBS} ${PTHREAD_LIBS} ${LIBMNL_LIBS}

