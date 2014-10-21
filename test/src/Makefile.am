check_PROGRAMS = unit_identity.out unit_neighbour.out unit_ifaddr.out unit_iface.out unit_data_tracker.out

AM_CFLAGS=${CURL_CFLAGS} ${PTHREAD_CFLAGS} ${LIBMNL_CFLAGS} -DSYSCONFDIR=\"${sysconfdir}\" -I../../src --coverage

unit_identity_out_SOURCES = unit_identity.c

unit_neighbour_out_SOURCES = unit_neighbour.c \
			 bindiff.c \
			 ../../src/configuration.c \
			 ../../src/ip.c \
			 ../../src/mnl_helpers.c \
			 ../../src/string_helpers.c \
			 ../../src/syslog_syserror.c
unit_neighbour_out_LDADD=${CURL_LIBS} ${PTHREAD_LIBS} ${LIBMNL_LIBS}

unit_ifaddr_out_SOURCES = unit_ifaddr.c \
			 bindiff.c \
			 ../../src/configuration.c \
			 ../../src/ip.c \
			 ../../src/mnl_helpers.c \
			 ../../src/string_helpers.c \
			 ../../src/syslog_syserror.c
unit_ifaddr_out_LDADD=${CURL_LIBS} ${PTHREAD_LIBS} ${LIBMNL_LIBS}

unit_iface_out_SOURCES = unit_iface.c \
			 bindiff.c \
			 ../../src/configuration.c \
			 ../../src/ip.c \
			 ../../src/mnl_helpers.c \
			 ../../src/string_helpers.c \
			 ../../src/syslog_syserror.c
unit_iface_out_LDADD=${CURL_LIBS} ${PTHREAD_LIBS} ${LIBMNL_LIBS}

unit_data_tracker_out_SOURCES = unit_data_tracker.c \
				bindiff.c \
				../../src/mnl_helpers.c \
				../../src/string_helpers.c \
				../../src/syslog_syserror.c
unit_data_tracker_out_LDADD = ${CURL_LIBS} ${PTHREAD_LIBS} ${LIBMNL_LIBS}

CLEANFILES = *.gcda *.gcno *.gcov

