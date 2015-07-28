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
#----------------
#
# AX_CONFIG_OPTION_STRING_NN
#
# USAGE
# 	AX_CONFIG_OPTION_STRING_NN(string_name, default_value [, readable_name [, type_hint [, help_string [, default_displayed]]]])
#
# DESCRIPTION
# 	Creates a configurable option containing a non-empty string.
#
#----------------
AC_DEFUN([AX_CONFIG_OPTION_STRING_NN],[
  AC_ARG_ENABLE([custom_$1],
    AC_HELP_STRING([--enable-custom-]m4_join([-], m4_unquote(m4_split([$1], [_])))[=]m4_default([$4],[STRING]), m4_default([$5], [set custom ]m4_default([$3], [$1]))[, default: ]m4_default([$6], [$2])),
    AS_CASE([${enableval}],
      [no], AS_VAR_SET([$1], [$2]),
      [yes], AC_MSG_ERROR([Custom ]m4_default([$3], [$1])[ not specified]),
      [""], AC_MSG_ERROR([Custom ]m4_default([$3], [$1])[ not specified]),
      AS_VAR_COPY([$1], [{enableval}])),
    AS_VAR_SET([$1], [$2]))
  AC_DEFINE_UNQUOTED([CONFIG_OPTION_]m4_toupper($1), "${$1}", m4_default([$3], [$1]))])
#----------------
#
# AX_CONFIG_OPTION_NUMBER_GE
#
# USAGE
# 	AX_CONFIG_OPTION_NUMBER_GE(string_name, default_value [, minimum [, readable_name [, type_hint [, help_string [, default_displayed]]]]])
#
# DESCRIPTION
# 	Creates a configurable option containing an integer greater than or
# 	equal to some minimum value.
# 	
#----------------
AC_DEFUN([AX_CONFIG_OPTION_NUMBER_GE],[
  AC_ARG_ENABLE([custom_$1],
    AC_HELP_STRING([--enable-custom-]m4_join([-], m4_unquote(m4_split([$1], [_])))[=]m4_default([$5],[INT]), m4_default([$6], [set custom ]m4_default([$4], [$1]))[, default: ]m4_default([$7], $2)[, minimum: ]m4_default([$3], [1])),
    AS_CASE([${enableval}],
      [no], AS_VAR_SET([$1], $2),
      [yes], AC_MSG_ERROR([Custom ]m4_default([$4], [$1])[ not specified]),
      [""], AC_MSG_ERROR([Custom ]m4_default([$4], [$1])[ not specified]),
      AS_IF([test "0${enableval}" -ge ]m4_default([$3], [1]),
        AS_VAR_COPY([$1], [{enableval}]),
	AC_MSG_ERROR([Custom ]m4_default([$4], [$1])[ must be at least ]m4_default([$3], [1])))),
    AS_VAR_SET([$1], $2))
  AC_DEFINE_UNQUOTED([CONFIG_OPTION_]m4_toupper($1), ${$1}, m4_default([$4], [$1]))])
#----------------
#
# AX_CONFIG_OPTION_NUMBER_RANGE
#
# USAGE
# 	AX_CONFIG_OPTION_NUMBER_RANGE(string_name, default_value, minimum, maximum [, readable_name [, type_hint [, help_string [, default_displayed]]]])
#
# DESCRIPTION
# 	Creates a configurable option containing an integer greater than or
# 	equal to some minimum value and less than or equal to some maximum
# 	value.
#
#----------------
AC_DEFUN([AX_CONFIG_OPTION_NUMBER_RANGE],[
  AC_ARG_ENABLE([custom_$1],
    AC_HELP_STRING([--enable-custom-]m4_join([-], m4_unquote(m4_split([$1], [_])))[=]m4_default([$6],[INT]), m4_default([$7], [set custom ]m4_default([$5], [$1]))[, default: ]m4_default([$8], $2)[, min: $3, max: $4]),
    AS_CASE([${enableval}],
      [no], AS_VAR_SET([$1], $2),
      [yes], AC_MSG_ERROR([Custom ]m4_default([$5], [$1])[ not specified]),
      [""], AC_MSG_ERROR([Custom ]m4_default([$5], [$1])[ not specified]),
      AS_IF([test "0${enableval}" -ge $3 && test "0${enableval}" -le $4],
        AS_VAR_COPY([$1], [{enableval}]),
	AC_MSG_ERROR([Custom ]m4_default([$5], [$1])[ must be between $3 and $4 ]))),
    AS_VAR_SET([$1], $2))
  AC_DEFINE_UNQUOTED([CONFIG_OPTION_]m4_toupper($1), ${$1}, m4_default([$5], [$1]))])
#----------------
#
# AX_CONFIG_OPTION_BOOL
#
# USAGE
# 	AX_CONFIG_OPTION_BOOL(string_name, default_value [, readable_name [, help_string [, default_displayed]]])
#
# DESCRIPTION
# 	Creates a configurable option containing a boolean value.
#
#----------------
AC_DEFUN([AX_CONFIG_OPTION_BOOL],[
  AC_ARG_ENABLE([$1],
    AC_HELP_STRING([--enable-]m4_join([-], m4_unquote(m4_split([$1], [_]))), m4_default([$4], [enable ]m4_default([$3], [$1]))[, default: ]m4_default([$5], [$2])),
    AS_CASE([${enableval}],
      [no], AS_VAR_SET([$1], 0),
      [yes], AS_VAR_SET([$1], 1),
      [""], AS_VAR_SET([$1], 1),
      AC_MSG_ERROR([Only "yes" and "no" are accepted as values for ]m4_default([$3], [$1]))),
    AS_IF([test "x$2" == xyes], AS_VAR_SET([$1], 1), AS_VAR_SET([$1], 0)))
  AC_DEFINE_UNQUOTED([CONFIG_OPTION_]m4_toupper($1), ${$1}, m4_default([$3], [$1]))])
#----------------
