bin_PROGRAMS = wiomw-plugin

wiomw_plugin_SOURCES = main.c \
		       configuration.c \
		       signal_handler.c \
		       print_error.c \
		       api.c \
		       neighbours.c \
		       sockaddr_helpers.c \
		       mac_ntop.c
AM_CFLAGS=${CURL_CFLAGS} ${PTHREAD_CFLAGS} ${LIBMNL_CFLAGS}
wiomw_plugin_LDADD=${CURL_LIBS} ${PTHREAD_LIBS} ${LIBMNL_LIBS}

