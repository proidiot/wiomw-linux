bin_PROGRAMS = wiomw-plugin

wiomw_plugin_SOURCES = main.c \
		       configuration.c \
		       signal_handler.c \
		       print_error.c \
		       api.c \
		       neighbours.c \
		       sockaddr_helpers.c
#AM_CFLAGS=${CURL_CFLAGS} ${PTHREAD_CFLAGS} ${LIBNL3_CFLAGS}
AM_CFLAGS=${CURL_CFLAGS} ${PTHREAD_CFLAGS} -isystem /usr/include/libnl3
LIBS+=${CURL_LIBS} ${PTHREAD_LIBS} ${LIBNL3_LIBS}

