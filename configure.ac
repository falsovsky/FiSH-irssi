AC_PREREQ([2.65])
AC_INIT([libfish], [1.0], [falsovsky@gmail.com], [FiSH irssi module])
AC_CONFIG_SRCDIR([src/FiSH.c])
AC_CONFIG_HEADERS([src/config.h])

AC_PROG_CC
#AC_PROG_RANLIB
LT_INIT

AM_INIT_AUTOMAKE([1.9])

AC_LANG([C])

#AC_PROG_LIBTOOL

#AC_DEFINE([FiSH_USE_IRSSI_RECODE], [1], [irssi unicode support])
#AC_DEFINE([FiSH_DECRYPT_ZNC_LOGS], [0], [ZNC log support])


AC_ARG_ENABLE([irssi-recode], 
              AS_HELP_STRING([--disable-irssi-recode],[disable irssi unicode recode]),
              [AC_DEFINE([FiSH_USE_IRSSI_RECODE], [0], [irssi unicode support])],
              [AC_DEFINE([FiSH_USE_IRSSI_RECODE], [1], [irssi unicode support])] )

AC_ARG_ENABLE([znc-logs],
              AS_HELP_STRING([--enable-znc-logs],[enable ZNC logs support]),
              AC_DEFINE([FiSH_DECRYPT_ZNC_LOGS], [1], [ZNC log support]),
              [AC_DEFINE([FiSH_DECRYPT_ZNC_LOGS], [0], [ZNC log support])])

AC_CHECK_LIB(gmp, __gmpz_init, , [AC_MSG_ERROR(
                                  [GNU MP not found, see http://swox.com/gmp])])
AC_ARG_WITH(irssi-prefix,
            AC_HELP_STRING([--with-irssi-prefix],[path for irssi source code]), 
            [IRSSI_PATH=${withval}
             AC_SUBST(IRSSI_PATH)],
             [AC_MSG_ERROR(Please define irssi source path. eg: --with-irssi-prefix=/usr/include/irssi)])

PKG_CHECK_EXISTS([glib-2.0], [
                  GLIB_CFLAGS=`pkg-config glib-2.0 --cflags`
                  AC_SUBST(GLIB_CFLAGS)
                  ], [AC_MSG_ERROR([glib-2.0 is not installed])])


AC_CHECK_HEADERS([stddef.h stdlib.h string.h unistd.h])

AC_TYPE_SIZE_T

AC_FUNC_MALLOC
AC_CHECK_FUNCS([getpass memmove memset strcasecmp strchr strncasecmp strrchr strspn strstr])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_OUTPUT
