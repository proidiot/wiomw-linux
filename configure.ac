#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([wiomw-plugin], [1.0], [support@io3o.com])
AC_CONFIG_MACRO_DIR[(m4])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for libraries.
AC_CHECK_LIB([m], [rint])
PKG_CHECK_MODULES([CURL], [libcurl])
AC_ARG_WITH([openssl],
   AC_HELP_STRING([--with-openssl],
      [assume cURL uses OpenSSL and not PolarSSL, default: no]),
   [case "${withval}" in
      no)  with_polarssl=check;;
      yes) with_polarssl=no;;
      *)   AC_MSG_ERROR([Custom OpenSSL path not yet supported]);;
    esac],
   [with_polarssl=check])
AC_CHECK_LIB([polarssl], [ssl_init])
AS_IF([test "x$with_polarssl" != xno],
   [AC_CHECK_LIB([polarssl], [ssl_init],
      [with_openssl=no], [with_openssl=check])],
   [with_openssl=check])
AS_IF([test "x$with_openssl" != xno],
   [AC_CHECK_LIB([ssl], [SSL_library_init],
      [found_ssl=yes], [found_ssl=no])],
   [found_ssl=yes])
AS_IF([test "x$found_ssl" = xno],
   [AC_MSG_ERROR([Neither PolarSSL nor OpenSSL was found])],
   [])
#AX_PTHREAD
PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0])
AC_CHECK_LIB([yajl_s], [yajl_tree_parse])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h stdint.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AX_CFLAGS_WARN_ALL_EXTRA

# Checks for library functions.
#AC_FUNC_MALLOC
#AC_FUNC_REALLOC
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([alarm getpagesize malloc memset realloc regcomp socket strnlen])

# Get PERMANENT_IFACE_BLACKLIST_REGEX
AC_ARG_ENABLE([custom_permanent_iface_blacklist_regex],
   AC_HELP_STRING([--enable-custom-permanent-iface-blacklist-regex=REGEX],
      [set a permanent interface blacklist regular expression, default: '^virbr@<:@0-9@:>@+$']),
   [case "${enableval}" in
      no)  permanent_iface_blacklist_regex='^virbr@<:@0-9@:>@+$';;
      yes) AC_MSG_ERROR([Custom permanent interface blacklist regular expression was not specified]);;
      "")  AC_MSG_ERROR([Custom permanent interface blacklist regular expression was not specified]);;
      *)   permanent_iface_blacklist_regex=${enableval};;
      esac],
   [permanent_iface_blacklist_regex='^virbr@<:@0-9@:>@+$'])
AC_DEFINE_UNQUOTED(PERMANENT_IFACE_BLACKLIST_REGEX, "${permanent_iface_blacklist_regex}",
   [Permanent interface blacklist regular expression])
permanent_iface_blacklist_regex_length=`echo $permanent_iface_blacklist_regex | wc -m`;
AC_DEFINE_UNQUOTED(PERMANENT_IFACE_BLACKLIST_REGEX_LENGTH, ${permanent_iface_blacklist_regex_length},
   [Permanent interface blacklist regular expression length])

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

# Get MAX_IFACE_BLACKLIST_REGEX_LENGTH
AC_ARG_ENABLE([custom_iface_blacklist_regex_length],
   AC_HELP_STRING([--enable-custom-iface-blacklist-regex-length=BYTES],
      [set maximum length of the interface blacklist regular expression, default: 128]),
   [case "${enableval}" in
      no)  max_iface_blacklist_regex_length=128;;
      yes) AC_MSG_ERROR([Custom interface blacklist regular expression length was not specified]);;
      "")  AC_MSG_ERROR([Custom interface blacklist regular expression length was not specified]);;
      *)   if test "0${enableval}" -gt 0;
              then max_iface_blacklist_regex_length=${enableval};
              else AC_MSG_ERROR([Interface blacklist regular expression length must be a number greater than 0]);
              fi;;
      esac],
   [max_iface_blacklist_regex_length=128])
AC_DEFINE_UNQUOTED(MAX_IFACE_BLACKLIST_REGEX_LENGTH, ${max_iface_blacklist_regex_length},
   [Maximum interface blacklist regular expression length])

# Get MAX_API_URL_LENGTH
AC_ARG_ENABLE([custom_api_url_length],
   AC_HELP_STRING([--enable-custom-api-url-length=BYTES],
      [set maximum length of the API URL, default: 4096]),
   [case "${enableval}" in
      no)  max_api_url_length=4096;;
      yes) AC_MSG_ERROR([Custom API URL length was not specified]);;
      "")  AC_MSG_ERROR([Custom API URL length was not specified]);;
      *)   if test "0${enableval}" -gt 0;
              then max_api_url_length=${enableval};
              else AC_MSG_ERROR([API URL length must be a number greater than 0]);
              fi;;
      esac],
   [max_api_url_length=4096])
AC_DEFINE_UNQUOTED(MAX_API_URL_LENGTH, ${max_api_url_length},
   [Maximum API URL length])

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

# Get MINIMUM_IPV4_PUBLIC_PREFIX
AC_ARG_ENABLE([custom_minimum_ipv4_public_prefix],
   AC_HELP_STRING([--enable-custom-minimum-ipv4-public-prefix=BITS],
      [set minimum IPv4 public prefix, default: 32]),
   [case "${enableval}" in
      no)  minimum_ipv4_public_prefix=32;;
      yes) AC_MSG_ERROR([Custom minimum IPv4 public prefix was not specified]);;
      "")  AC_MSG_ERROR([Custom minimum IPv4 public prefix was not specified]);;
      *)   if test "0${enableval}" -gt 0;
              then minimum_ipv4_public_prefix=${enableval};
              else AC_MSG_ERROR([Minimum IPv4 public prefix must be a number greater than 0]);
              fi;;
      esac],
   [minimum_ipv4_public_prefix=32])
AC_DEFINE_UNQUOTED(MINIMUM_IPV4_PUBLIC_PREFIX, ${minimum_ipv4_public_prefix},
   [Minimum IPv4 public prefix])

# Get MINIMUM_IPV6_PUBLIC_PREFIX
AC_ARG_ENABLE([custom_minimum_ipv6_public_prefix],
   AC_HELP_STRING([--enable-custom-minimum-ipv6-public-prefix=BITS],
      [set minimum IPv6 public prefix, default: 128]),
   [case "${enableval}" in
      no)  minimum_ipv6_public_prefix=128;;
      yes) AC_MSG_ERROR([Custom minimum IPv6 public prefix was not specified]);;
      "")  AC_MSG_ERROR([Custom minimum IPv6 public prefix was not specified]);;
      *)   if test "0${enableval}" -gt 0;
              then minimum_ipv6_public_prefix=${enableval};
              else AC_MSG_ERROR([Minimum IPv6 public prefix must be a number greater than 0]);
              fi;;
      esac],
   [minimum_ipv6_public_prefix=128])
AC_DEFINE_UNQUOTED(MINIMUM_IPV6_PUBLIC_PREFIX, ${minimum_ipv6_public_prefix},
   [Minimum IPv6 public prefix])

# Get CONFIG_FILE_LOCATION
AC_ARG_ENABLE([custom_config_file],
   AC_HELP_STRING([--enable-custom-config-file=/PATH/TO/FILE.CONF],
      [set config file location, default: SYSCONFDIR/wiomw.conf]),
   [case "${enableval}" in
      no)  config_file_location="\"SYSCONFDIR\"/wiomw.conf";;
      yes) AC_MSG_ERROR([Custom config file location was not specified]);;
      "")  AC_MSG_ERROR([Custom config file location was not specified]);;
      *)   config_file_location="${enableval}";;
      esac],
   [config_file_location="\"SYSCONFDIR\"/wiomw.conf"])
AC_DEFINE_UNQUOTED(CONFIG_FILE_LOCATION, "${config_file_location}",
    [Location of config file])

# Get IPTABLES_COMMAND
AC_ARG_ENABLE([custom_iptables_command],
   AC_HELP_STRING([--enable-custom-iptables-command=COMMAND],
      [set iptables command, default: iptables (NOTE: set the full path for improved security)]),
   [case "${enableval}" in
      no)  iptables_command="iptables";;
      yes) AC_MSG_ERROR([Custom iptables command was not specified]);;
      "")  AC_MSG_ERROR([Custom iptables command was not specified]);;
      *)   iptables_command="${enableval}";;
      esac],
   [iptables_command="iptables"])
AC_DEFINE_UNQUOTED(IPTABLES_COMMAND, "${iptables_command}",
    [Command to run for iptables, hopefully with a full path specified])

# Get SESSION_LENGTH
AC_ARG_ENABLE([custom_session_length],
   AC_HELP_STRING([--enable-custom-session-length=SECS],
      [set session length, default: 288000 (i.e. 8 hours)]),
   [case "${enableval}" in
      no)  session_length=288000;;
      yes) AC_MSG_ERROR([Custom session length was not specified]);;
      "")  AC_MSG_ERROR([Custom session length was not specified]);;
      *)   if test "0${enableval}" -gt 300;
              then session_length=${enableval};
              else AC_MSG_ERROR([Session length must be at least 5 minutes]);
              fi;;
      esac],
   [session_length=288000])
AC_DEFINE_UNQUOTED(SESSION_LENGTH, ${session_length},
   [Wait period between wiomw_login calls])


# Get SYNC_BLOCK_FREQUENCY
AC_ARG_ENABLE([custom_sync_block_frequency],
   AC_HELP_STRING([--enable-custom-sync-block-frequency=SECS],
      [set sync_block frequency, default: 300 (i.e. 5 mins)]),
   [case "${enableval}" in
      no)  sync_block_frequency=300;;
      yes) AC_MSG_ERROR([Custom sync_block frequency was not specified]);;
      "")  AC_MSG_ERROR([Custom sync_block frequency was not specified]);;
      *)   if test "0${enableval}" -gt 0;
              then sync_block_frequency=${enableval};
              else AC_MSG_ERROR([Frequency of sync_block must be at least 1 second]);
              fi;;
      esac],
   [sync_block_frequency=300])
AC_DEFINE_UNQUOTED(SYNC_BLOCK_FREQUENCY, ${sync_block_frequency},
   [Wait period between sync_block calls])

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
      [set login API URL, default: https://www.whoisonmywifi.net/api/v100/rest/login]),
   [case "${enableval}" in
      no)  login_url="https://www.whoisonmywifi.net/api/v100/rest/login";;
      yes) AC_MSG_ERROR([Custom login API URL was not specified]);;
      "")  AC_MSG_ERROR([Custom login API URL was not specified]);;
      *)   login_url="${enableval}";;
      esac],
   [login_url="https://www.whoisonmywifi.net/api/v100/rest/login"])
AC_DEFINE_UNQUOTED(LOGIN_API_URL, "${login_url}",
    [URL of login API])

# Get SYNC_BLOCK_URL
AC_ARG_ENABLE([custom_sync_block_url],
   AC_HELP_STRING([--enable-custom-sync-block-url=URL],
      [set sync_block API URL, default: https://www.whoisonmywifi.net/api/v100/rest/sync_block]),
   [case "${enableval}" in
      no)  sync_block_url="https://www.whoisonmywifi.net/api/v100/rest/sync_block";;
      yes) AC_MSG_ERROR([Custom sync_block API URL was not specified]);;
      "")  AC_MSG_ERROR([Custom sync_block API URL was not specified]);;
      *)   sync_block_url="${enableval}";;
      esac],
   [sync_block_url="https://www.whoisonmywifi.net/api/v100/rest/sync_block"])
AC_DEFINE_UNQUOTED(SYNC_BLOCK_API_URL, "${sync_block_url}",
    [URL of sync_block API])

# Get SEND_DEVICES_URL
AC_ARG_ENABLE([custom_send_devices_url],
   AC_HELP_STRING([--enable-custom-send-devices-url=URL],
      [set send devices API URL, default: https://www.whoisonmywifi.net/api/v100/rest/senddevice]),
   [case "${enableval}" in
      no)  send_devices_url="https://www.whoisonmywifi.net/api/v100/rest/senddevice";;
      yes) AC_MSG_ERROR([Custom send devices API URL was not specified]);;
      "")  AC_MSG_ERROR([Custom send devices API URL was not specified]);;
      *)   send_devices_url="${enableval}";;
      esac],
   [send_devices_url="https://www.whoisonmywifi.net/api/v100/rest/senddevice"])
AC_DEFINE_UNQUOTED(SEND_DEVICES_API_URL, "${send_devices_url}",
    [URL of send devices API])

# Get WIOMW_AGENT_TYPE
AC_ARG_ENABLE([custom_agent_type],
   AC_HELP_STRING([--enable-custom-agent-type=STRING],
      [wiomw agent type, default: linux]),
   [case "${enableval}" in
      no)  wiomw_agent_type="linux";;
      yes) AC_MSG_ERROR([Custom agent type was not specified]);;
      "")  AC_MSG_ERROR([Custom agent type was not specified]);;
      *)   wiomw_agent_type="${enableval}";;
      esac],
   [wiomw_agent_type="linux"])
AC_DEFINE_UNQUOTED(WIOMW_AGENT_TYPE, "${wiomwi_agent_type}",
    [wiomw agent type])


AC_CONFIG_FILES([Makefile
                 etc/Makefile
                 src/Makefile])
AC_OUTPUT
