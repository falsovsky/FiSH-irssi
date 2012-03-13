AC_PREREQ([2.59])
AC_INIT([libfish], [1.1], [falsovsky@gmail.com], [FiSH irssi module])
AC_CONFIG_SRCDIR([src/FiSH.c])
AC_CONFIG_HEADERS([src/config.h])

AC_PROG_CC
AC_PROG_LIBTOOL

AM_INIT_AUTOMAKE([1.9])

AC_CONFIG_MACRO_DIR([m4])

AC_ARG_ENABLE([irssi-recode], 
              AS_HELP_STRING([--disable-irssi-recode],[disable irssi unicode recode]),
              [AC_DEFINE([FiSH_USE_IRSSI_RECODE], [0], [irssi unicode support])],
              [AC_DEFINE([FiSH_USE_IRSSI_RECODE], [1], [irssi unicode support])])

AC_ARG_ENABLE([znc-logs],
              AS_HELP_STRING([--enable-znc-logs],[enable ZNC logs support]),
              AC_DEFINE([FiSH_DECRYPT_ZNC_LOGS], [1], [ZNC log support]),
              [AC_DEFINE([FiSH_DECRYPT_ZNC_LOGS], [0], [ZNC log support])])

AC_ARG_WITH([gmp_include],
            [AC_HELP_STRING([--with-gmp-include=DIR],
                            [GMP include directory])],
            [CPPFLAGS="-I$withval $CPPFLAGS"])
AC_ARG_WITH([gmp_lib],
            [AC_HELP_STRING([--with-gmp-lib=DIR],
                            [GMP lib directory])],
            [LDFLAGS="-L$withval $LDFLAGS"])
AC_ARG_WITH([gmp],
            [AC_HELP_STRING([--with-gmp=DIR],
                           [GMP install directory])],
            [
            if test -z "$with_gmp_lib" -a -z "$with_gmp_include" ; then
               CPPFLAGS="-I$withval/include $CPPFLAGS"
               LDFLAGS="-L$withval/lib $LDFLAGS"
            else
               AC_MSG_FAILURE([Do not use --with-gmp and --with-gmp-include/--with-gmp-lib options simultaneously.])
            fi
            ])

#PKG_CHECK_MODULES(OPENSSL, [openssl], [], [CHECK_SSL()])
m4_include([m4/ax_check_openssl.m4])
PKG_CHECK_MODULES(OPENSSL, [openssl], , [CHECK_SSL()])

AC_CHECK_LIB(gmp, __gmpz_init, , [AC_MSG_ERROR(
                                  [GNU MP not found, see http://swox.com/gmp])])

AC_ARG_WITH([irssi-source],
            AC_HELP_STRING([--with-irssi-source=DIR],[irssi source directory]), 
            [IRSSI_PATH=${withval}
             AC_SUBST(IRSSI_PATH)],
             [AC_MSG_ERROR([To build FiSH you will need the irssi source code, please download it and extract it on a desired location.
Then re-run this configure script with --with-irssi-source=/path/to/irssi/source.
eg: ./configure --with-irssi-source=/home/falso/src/irssi-0.8.15])])

PKG_CHECK_EXISTS([glib-2.0], [
                  GLIB_CFLAGS=`pkg-config glib-2.0 --cflags`
                  AC_SUBST(GLIB_CFLAGS)
                  ], [AC_MSG_ERROR([glib-2.0 is not installed])])


AC_CHECK_HEADERS([stddef.h stdlib.h string.h unistd.h])

AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(long long)
AC_CHECK_SIZEOF(off_t)

if test $ac_cv_sizeof_off_t = 8; then
  offt_64bit=yes
else
  offt_64bit=no
fi

if test x$ac_cv_sizeof_off_t = x$ac_cv_sizeof_long; then
  # try to use unsigned long always first
  AC_DEFINE_UNQUOTED(PRIuUOFF_T, "lu")
  AC_DEFINE(UOFF_T_LONG)
elif test x$ac_cv_sizeof_off_t = x$ac_cv_sizeof_int; then
  # next try int
  AC_DEFINE_UNQUOTED(PRIuUOFF_T, "u")
  AC_DEFINE(UOFF_T_INT)
elif test x$ac_cv_sizeof_off_t = x$ac_cv_sizeof_long_long; then
  # and finally long long
  AC_DEFINE_UNQUOTED(PRIuUOFF_T, "llu")
  AC_DEFINE(UOFF_T_LONG_LONG)
else
  AC_ERROR([Couldn't find integer type for off_t])
fi

AC_TYPE_SIZE_T

AC_FUNC_MALLOC
AC_CHECK_FUNCS([getpass memmove memset strcasecmp strchr strncasecmp strrchr strspn strstr])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_OUTPUT
