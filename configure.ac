#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([wiomw-plugin], [0.1], [support@io3o.com])
AC_CONFIG_MACRO_DIR[(m4])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h src/configuration.h])
AM_INIT_AUTOMAKE([-Wall -Werror])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for libraries.
PKG_CHECK_MODULES([CURL], [libcurl])
AC_CHECK_LIB([polarssl], [ssl_init])
AX_PTHREAD
PKG_CHECK_MODULES([LIBNL3], [libnl-3.0 >= 3.1, libnl-route-3.0 >= 3.1])
AC_CHECK_LIB([m], [rint])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h stdint.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AX_CFLAGS_WARN_ALL_EXTRA

# Checks for library functions.
#AC_FUNC_MALLOC
#AC_FUNC_REALLOC
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([alarm malloc memset realloc regcomp socket])

# Get MAX_USERNAME_LENGTH
AC_ARG_ENABLE([custom_username_length],
   AC_HELP_STRING([--enable-custom-username-length=BYTES],
      [set maximum username length, default: 1024]),
   [case "${enableval}" in
      no)  max_username_length=1024;;
      yes) AC_MSG_ERROR([Custom username length was not specified]);;
      "")  AC_MSG_ERROR([Custom username length was not specified]);;
      *)   if test "0${enableval}" -gt 0;
              then max_username_length=${enableval};
              else AC_MSG_ERROR([Username length must be a number greater than 0]);
              fi;;
      esac],
   [max_username_length=1024])
AC_DEFINE_UNQUOTED(MAX_USERNAME_LENGTH, ${max_username_length},
   [Maximum username length])

# Get MAX_PASSHASH_LENGTH
AC_ARG_ENABLE([custom_passhash_length],
   AC_HELP_STRING([--enable-custom-passhash-length=BYTES],
      [set maximum passhash length, default: 1024]),
   [case "${enableval}" in
      no)  max_passhash_length=1024;;
      yes) AC_MSG_ERROR([Custom passhash length was not specified]);;
      "")  AC_MSG_ERROR([Custom passhash length was not specified]);;
      *)   if "0${enableval}" -gt 0;
              then max_passhash_length=${enableval};
              else AC_MSG_ERROR([Passhash length must be a number greater than 0]);
              fi;;
      esac],
   [max_passhash_length=1024])
AC_DEFINE_UNQUOTED(MAX_PASSHASH_LENGTH, ${max_passhash_length},
   [Maximum passhash length])

# Get MAX_SESSION_ID_LENGTH
AC_ARG_ENABLE([custom_session_id_length],
   AC_HELP_STRING([--enable-custom-session-id-length=BYTES],
      [set maximum length of the session ID, default: 4096]),
   [case "${enableval}" in
      no)  max_session_id_length=4096;;
      yes) AC_MSG_ERROR([Custom session ID length was not specified]);;
      "")  AC_MSG_ERROR([Custom session ID length was not specified]);;
      *)   if test "0${enableval}" -gt 0;
              then max_session_id_length=${enableval};
              else AC_MSG_ERROR([Session ID length must be a number greater than 0]);
              fi;;
      esac],
   [max_session_id_length=4096])
AC_DEFINE_UNQUOTED(MAX_SESSION_ID_LENGTH, ${max_session_id_length},
   [Maximum session ID length])

# Get MAX_CONFIG_LINE_LENGTH
AC_ARG_ENABLE([custom_config_line_length],
   AC_HELP_STRING([--enable-custom-config-line-length=BYTES],
      [set maximum length of any line in the configuration file, default: 4096]),
   [case "${enableval}" in
      no)  max_config_line_length=4096;;
      yes) AC_MSG_ERROR([Custom config line length was not specified]);;
      "")  AC_MSG_ERROR([Custom config line length was not specified]);;
      *)   if test "0${enableval}" -gt 0;
              then max_config_line_length=${enableval};
              else AC_MSG_ERROR([Config line length must be a number greater than 0]);
              fi;;
      esac],
   [max_config_line_length=4096])
AC_DEFINE_UNQUOTED(MAX_CONFIG_LINE_LENGTH, ${max_config_line_length},
   [Maximum config line length])

# Get CONFIG_FILE_LOCATION
AC_ARG_ENABLE([custom_config_file],
   AC_HELP_STRING([--enable-custom-config-file=/PATH/TO/FILE.CONF],
      [set config file location, default: /jffs/etc/wiomw.conf]),
   [case "${enableval}" in
      no)  config_file_location="/jffs/etc/wiomw.conf";;
      yes) AC_MSG_ERROR([Custom config file location was not specified]);;
      "")  AC_MSG_ERROR([Custom config file location was not specified]);;
      *)   config_file_location="${enableval}";;
      esac],
   [config_file_location="/jffs/etc/wiomw.conf"])
AC_DEFINE_UNQUOTED(CONFIG_FILE_LOCATION, "${config_file_location}",
    [Location of config file])

# Get GET_UPDATES_FREQUENCY
AC_ARG_ENABLE([custom_get_updates_frequency],
   AC_HELP_STRING([--enable-custom-get-updates-frequency=SECS],
      [set get_updates frequency, default: 300 (i.e. 5 mins)]),
   [case "${enableval}" in
      no)  get_updates_frequency=300;;
      yes) AC_MSG_ERROR([Custom get_updates frequency was not specified]);;
      "")  AC_MSG_ERROR([Custom get_updates frequency was not specified]);;
      *)   if test "0${enableval}" -gt 0;
              then get_updates_frequency=${enableval};
              else AC_MSG_ERROR([Frequency of get_updates must be at least 1 second]);
              fi;;
      esac],
   [get_updates_frequency=300])
AC_DEFINE_UNQUOTED(GET_UPDATES_FREQUENCY, ${get_updates_frequency},
   [Wait period between get_updates calls])

# Get HANDLE_SIGQUIT
AC_ARG_ENABLE([sigquit-handling],
   AC_HELP_STRING([--enable-sigquit-handling],
      [handle SIGQUIT in the same way as SIGTERM and SIGINT, default: no]),
   [case "${enableval}" in
      no)  handle_sigquit=0;;
      yes) handle_sigquit=1;;
      "")  AC_MSG_ERROR([SIGQUIT handling decision was not specified]);;
      *)   AC_MSG_ERROR([Unexpected value for --enable-sigquit-handling ]);;
    esac],
   [handle_sigquit=0])
AC_DEFINE_UNQUOTED(SHOULD_HANDLE_SIGQUIT, ${handle_sigquit}, [Handle SIGQUIT])

# Get LOGIN_URL
AC_ARG_ENABLE([custom_login_url],
   AC_HELP_STRING([--enable-custom-login-url=URL],
      [set login API URL, default: https://www.whoisonmywifi.net/api/rest/login]),
   [case "${enableval}" in
      no)  login_url="https://www.whoisonmywifi.net/api/rest/login";;
      yes) AC_MSG_ERROR([Custom login API URL was not specified]);;
      "")  AC_MSG_ERROR([Custom login API URL was not specified]);;
      *)   login_url="${enableval}";;
      esac],
   [login_url="https://www.whoisonmywifi.net/api/rest/login"])
AC_DEFINE_UNQUOTED(LOGIN_API_URL, "${login_url}",
    [URL of login API])

# Get GET_UPDATES_URL
AC_ARG_ENABLE([custom_get_updates_url],
   AC_HELP_STRING([--enable-custom-get-updates-url=URL],
      [set get updates API URL, default: https://www.whoisonmywifi.net/api/rest/getupdate]),
   [case "${enableval}" in
      no)  get_updates_url="https://www.whoisonmywifi.net/api/rest/getupdate";;
      yes) AC_MSG_ERROR([Custom get updates API URL was not specified]);;
      "")  AC_MSG_ERROR([Custom get updates API URL was not specified]);;
      *)   get_updates_url="${enableval}";;
      esac],
   [get_updates_url="https://www.whoisonmywifi.net/api/rest/getupdate"])
AC_DEFINE_UNQUOTED(GET_UPDATES_API_URL, "${get_updates_url}",
    [URL of get updates API])

# Get SEND_UPDATES_URL
AC_ARG_ENABLE([custom_send_updates_url],
   AC_HELP_STRING([--enable-custom-send-updates-url=URL],
      [set send updates API URL, default: https://www.whoisonmywifi.net/api/rest/senddevice]),
   [case "${enableval}" in
      no)  send_updates_url="https://www.whoisonmywifi.net/api/rest/senddevice";;
      yes) AC_MSG_ERROR([Custom send updates API URL was not specified]);;
      "")  AC_MSG_ERROR([Custom send updates API URL was not specified]);;
      *)   send_updates_url="${enableval}";;
      esac],
   [send_updates_url="https://www.whoisonmywifi.net/api/rest/senddevice"])
AC_DEFINE_UNQUOTED(SEND_UPDATES_API_URL, "${send_updates_url}",
    [URL of send updates API])


AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
