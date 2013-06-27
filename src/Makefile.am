bin_PROGRAMS = wiomw-plugin

wiomw_plugin_SOURCES = main.c \
		       configuration.c \
		       signal_handler.c \
		       print_error.c \
		       api.c \
		       neighbours.c
#AM_CFLAGS=${CURL_CFLAGS} ${LIBNL3_CFLAGS}
AM_CFLAGS=${CURL_CFLAGS} -isystem /usr/include/libnl3
LIBS+=${CURL_LIBS} ${LIBNL3_LIBS}

