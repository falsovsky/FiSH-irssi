AC_PREREQ([2.65])
AC_INIT([libfish], [1.0], [falsovsky@gmail.com], [FiSH irssi module])
AC_CONFIG_SRCDIR([src/FiSH.c])
AC_CONFIG_HEADERS([src/config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB

AM_INIT_AUTOMAKE([1.9])

AC_LANG([C])

AC_PROG_LIBTOOL

AC_ARG_ENABLE([irssi-recode], 
              AS_HELP_STRING([--disable-irssi-recode],[disable irssi unicode recode]),
              [], AC_DEFINE([FiSH_DECRYPT_ZNC_LOGS], [], [irssi unicode support]))

AC_ARG_ENABLE([znc-logs],
              AS_HELP_STRING([--enable-znc-logs],[enable ZNC logs support(?)]),
              AC_DEFINE([FiSH_DECRYPT_ZNC_LOGS], [], [ZNC log support]), [])

# Checks for libraries.
AC_CHECK_LIB(gmp, __gmpz_init, , [AC_MSG_ERROR(
                                  [GNU MP not found, see http://swox.com/gmp])])
PKG_CHECK_EXISTS([glib-2.0], [
                  GLIB_CFLAGS=`pkg-config glib-2.0 --cflags`
                  GLIB_LDFLAGS=`pkg-config glib-2.0 --libs`
                  AC_SUBST(GLIB_LDFLAGS)
                  AC_SUBST(GLIB_CFLAGS)
                  ], [AC_MSG_ERROR([glib-2.0 is not installed])])


# Checks for header files.
AC_CHECK_HEADERS([stddef.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([getpass memmove memset strcasecmp strchr strncasecmp strrchr strspn strstr])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_OUTPUT
