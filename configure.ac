#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([wiomw],
	[1.0],
	[support@io3o.com],
	[wiomw],
	[http://www.whoisonmywifi.net])
AC_CONFIG_MACRO_DIR[(m4])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for libraries.
AC_CHECK_LIB([m], [rint], ,AC_MSG_ERROR([libm was not found]))
PKG_CHECK_MODULES([CURL], [libcurl])
LIBCURL_CHECK_CONFIG
AS_IF([test "x$libcurl_protocol_HTTPS" != xyes || test "x$libcurl_feature_SSL" != xyes],
      [AC_MSG_ERROR([libcurl does not have HTTPS support enabled])])
#AX_PTHREAD
PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0])
AC_ARG_WITH([static_yajl],
   AC_HELP_STRING([--with-static-yajl],
      [use the staticly-linked version of yajl even if the dynamically-linked version is available, default: no]),
   AS_CASE([${withval}],
      [no], AS_VAR_SET([static_yajl], [no]),
      [yes], AS_VAR_SET([static_yajl], [yes]),
      [""], AS_VAR_SET([static_yajl], [yes]),
      AC_MSG_ERROR([Custom path to yajl library is not yet supported])),
   AS_VAR_SET([static_yajl], [no]))
AS_IF([test "x$static_yajl" != xyes],
   [AC_CHECK_LIB([yajl], [yajl_tree_parse], ,
      [AC_CHECK_LIB([yajl_s], [yajl_tree_parse], ,
         AC_MSG_ERROR([Either a dynamic or static version of yajl is required]))])],
   [AC_CHECK_LIB([yajl_s], [yajl_tree_parse], ,
      AC_MSG_ERROR([No static version of yajl was found; perhaps you did not mean to use --with-static-yajl ?]))])
AX_CONFIG_OPTION_BOOL([uci],
	[no],
	[uci configuration storage])
AS_IF([test "0$uci" -eq 01],
   [AC_CHECK_LIB([uci], [uci_alloc_context], ,
      AC_MSG_ERROR([Unable to find libuci; perhaps you did not mean to use -enable-uci ?]))])


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h stdint.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
#AX_CFLAGS_WARN_ALL_EXTRA

# Checks for library functions.
#AC_FUNC_MALLOC
#AC_FUNC_REALLOC
AC_FUNC_STRERROR_R
#AC_FUNC_STRNLEN
AC_CHECK_FUNCS([alarm getpagesize malloc memset realloc regcomp socket strerror strnlen])



# Check for optional features and default overrides
#TODO: group these items in a more logical way

AX_CONFIG_OPTION_STRING_NN([permanent_iface_blacklist_regex],
	["^virbr@<:@0-9@:>@+$"],
	[permanent interface blacklist regular expression],
	[REGEX],
	[set a permanent interface blacklist regular expression])

permanent_iface_blacklist_regex_length=`echo $permanent_iface_blacklist_regex | wc -m`;
AC_DEFINE_UNQUOTED(CONFIG_OPTION_PERMANENT_IFACE_BLACKLIST_REGEX_LENGTH,
	${permanent_iface_blacklist_regex_length},
	[permanent interface blacklist regular expression length])

AX_CONFIG_OPTION_NUMBER_GE([username_length],
	1024,
	8,
	[maximum allowable username length],
	[BYTES])

AX_CONFIG_OPTION_NUMBER_GE([passhash_length],
	1024,
	40,
	[maximum allowable password hash length],
	[BYTES])

AX_CONFIG_OPTION_NUMBER_GE([session_id_length],
	4096,
	128,
	[maximum allowable session ID length],
	[BYTES])

AX_CONFIG_OPTION_NUMBER_GE([iface_blacklist_regex_length],
	128,
	4,
	[maximum allowable length of an interface blacklist regular expression defined at runtime],
	[BYTES])

AX_CONFIG_OPTION_NUMBER_GE([api_url_length],
	4096,
	60,
	[maximum allowable length of an API URL defined at runtime],
	[BYTES])

AX_CONFIG_OPTION_NUMBER_GE([config_line_length],
	4096,
	50,
	[maximum allowable length of any line in the configuration file],
	[BYTES])

AX_CONFIG_OPTION_NUMBER_RANGE([ipv4_public_prefix],
	32,
	24,
	32,
	[minimum prefix of a publicly-accessible IPv4 network specified at runtime that will be scanned],
	[BITS])

AX_CONFIG_OPTION_NUMBER_RANGE([ipv6_public_prefix],
	128,
	112,
	128,
	[minimum prefix of a publicly-accessible IPv6 network specified at runtime that will be scanned],
	[BITS])

AX_CONFIG_OPTION_STRING_NN([config_file],
	["\"SYSCONFDIR\"/wiomw.conf"],
	[config file location],
	[/PATH/TO/wiomw.conf],
	,
	[SYSCONFDIR/wiomw.conf])

AX_CONFIG_OPTION_STRING_NN([iptables_path],
	[iptables],
	[path to iptables executable],
	[/PATH/TO/iptables],
	,
	[(find iptables in $PATH, less secure)])


AX_CONFIG_OPTION_BOOL([nvram_config],
	[no],
	[nvram configutation storage])

AX_CONFIG_OPTION_STRING_NN([nvram_path],
	[nvram],
	[path to nvram command executable],
	[/PATH/TO/nvram],
	,
	[(find nvram in $PATH, less secure)])


AX_CONFIG_OPTION_NUMBER_GE([session_length],
	288000,
	300,
	[length of time (in seconds) before requesting a new session],
	[SECS],
	,
	[288000 (i.e. 8 hours)])


AX_CONFIG_OPTION_NUMBER_GE([sync_block_frequency],
	300,
	90,
	[length of time (in seconds) before resyncing with the server],
	[SECS],
	,
	[300 (i.e. 5 mins)])

AX_CONFIG_OPTION_STRING_NN([login_url],
	[https://www.whoisonmywifi.net/api/v100/rest/login],
	[URL of login API],
	[URL])

AX_CONFIG_OPTION_STRING_NN([config_agent_url],
	[https://www.whoisonmywifi.net/api/v100/rest/config_agent],
	[URL of config_agent API],
	[URL])

AX_CONFIG_OPTION_STRING_NN([sync_block_url],
	[https://www.whoisonmywifi.net/api/v100/rest/sync_block],
	[URL of sync_block API],
	[URL])

AX_CONFIG_OPTION_STRING_NN([send_devices_url],
	[https://www.whoisonmywifi.net/api/v100/rest/senddeivce],
	[URL of send devices API],
	[URL])

AX_CONFIG_OPTION_STRING_NN([agent_type],
	[linux],
	[agent type])

AX_CONFIG_OPTION_STRING_NN([dnsmasq_lease_file],
	[/var/lib/misc/dnsmasq.lease],
	[dnsmasq lease file location],
	[/PATH/TO/dnsmasq.lease])

AX_CONFIG_OPTION_BOOL([dnsmasq_lease_lookup],
	[no],
	[dnsmasq.lease-based hostname lookup])

AX_CONFIG_OPTION_BOOL([api_url_overrides],
	[no],
	[run time overriding of API URLs],
	[allow API URLs to be overridden at run time (potentially very dangerous)])

AX_CONFIG_OPTION_STRING_NN([ca_path],
	["\"SYSCONFDIR\"/ssl/certs/f081611a.0"],
	[path to the certificate authority file],
	[/PATH/TO/ca-bundle.crt],
	,
	[SYSCONFDIR/ssl/certs/CA_FILE])

AC_CONFIG_FILES([Makefile
                 etc/Makefile
                 etc/ssl/Makefile
                 etc/ssl/certs/Makefile
                 src/Makefile])
AC_OUTPUT
