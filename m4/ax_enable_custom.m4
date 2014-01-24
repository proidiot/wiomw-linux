#
# AX_ENABLE_CUSTOM_STRING(string_name, default_value [, readable_name [, type_hint [, help_string [, default_displayed]]]])
#----------------
AC_DEFUN([AX_ENABLE_CUSTOM_STRING],[
  AC_ARG_ENABLE([custom_$1],
    AC_HELP_STRING([--enable-custom-]m4_join([-], m4_unquote(m4_split([$1], [_])))[=]m4_default([$4],[STRING]), m4_default([$5], [set custom ]m4_default([$3], [$1]))[, default: ]m4_default([$6], [$2])),
    AS_CASE([${enableval}],
      [no], AS_VAR_SET([$1], [$2]),
      [yes], AC_MSG_ERROR([Custom ]m4_default([$3], [$1])[ not specified]),
      [""], AC_MSG_ERROR([Custom ]m4_default([$3], [$1])[ not specified]),
      AS_VAR_COPY([$1], [{enableval}])
    ),
    AS_VAR_SET([$1], [$2])
  )
  AC_DEFINE_UNQUOTED([CUSTOM_]m4_toupper($1), "${$1}", m4_default([$3], [$1]))
])
#
# AX_ENABLE_CUSTOM_NUMBER(string_name, default_value [, minimum [, readable_name [, type_hint [, help_string [, default_displayed]]]]])
#----------------
AC_DEFUN([AX_ENABLE_CUSTOM_NUMBER],[
  AC_ARG_ENABLE([custom_$1],
    AC_HELP_STRING([--enable-custom-]m4_join([-], m4_unquote(m4_split([$1], [_])))[=]m4_default([$5],[INT]), m4_default([$6], [set custom ]m4_default([$4], [$1]))[, default: ]m4_default([$7], $2)[, minimum: ]m4_default([$3], [1])),
    AS_CASE([${enableval}],
      [no], AS_VAR_SET([$1], $2),
      [yes], AC_MSG_ERROR([Custom ]m4_default([$4], [$1])[ not specified]),
      [""], AC_MSG_ERROR([Custom ]m4_default([$4], [$1])[ not specified]),
      AS_IF([test "0${enableval}" -ge ]m4_default([$3], [1]),
        AS_VAR_COPY([$1], [{enableval}]),
	AC_MSG_ERROR([Custom ]m4_default([$4], [$1])[ must be at least ]m4_default([$3], [1]))
      )
    ),
    AS_VAR_SET([$1], $2)
  )
  AC_DEFINE_UNQUOTED([CUSTOM_]m4_toupper($1), ${$1}, m4_default([$4], [$1]))
])
#
# AX_ENABLE_BOOL(string_name, default_value [, readable_name [, help_string [, default_displayed]]])
#----------------
AC_DEFUN([AX_ENABLE_BOOL],[
  AC_ARG_ENABLE([$1],
    AC_HELP_STRING([--enable-]m4_join([-], m4_unquote(m4_split([$1], [_]))), m4_default([$4], [enable ]m4_default([$3], [$1]))[, default: ]m4_default([$5], [$2])),
    AS_CASE([${enableval}],
      [no], AS_VAR_SET([$1], 0),
      [yes], AS_VAR_SET([$1], 1),
      [""], AS_VAR_SET([$1], 1),
      AC_MSG_ERROR([Only "yes" and "no" are accepted as values for ]m4_default([$3], [$1]))
    ),
    AS_IF([test "x$2" == xyes], AS_VAR_SET([$1], 1), AS_VAR_SET([$1], 0))
  )
  AC_DEFINE_UNQUOTED([ENABLE_]m4_toupper($1), ${$1}, m4_default([$3], [$1]))
])
