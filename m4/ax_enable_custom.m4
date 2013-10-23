# AX_ENABLE_CUSTOM_STRING(string_name, default_value [, help_string [, type_hint [, readable_name]]]) 
#----------------
AC_DEFUN([AX_ENABLE_CUSTOM_STRING],[
  AC_ARG_ENABLE([custom_$1],
    AC_HELP_STRING([--enable-custom-]m4_join([-], m4_unquote(m4_split([$1], [_])))[=]m4_default([$4],[STRING]), m4_default([$3], [set custom $1])[, default: $2]),
    AS_CASE([${enableval}],
      [no], AS_VAR_SET([$1], [$2]),
      [yes], AC_MSG_ERROR([Custom ]m4_default([$5], [$1])[ not specified]),
      [""], AC_MSG_ERROR([Custom ]m4_default([$5], [$1])[ not specified]),
      AS_VAR_COPY([$1], [{enableval}])
    ),
    AS_VAR_SET([$1], [$2])
  )
  AC_DEFINE_UNQUOTED(m4_toupper($1), "${$1}", m4_default([$5], [$1]))
])
