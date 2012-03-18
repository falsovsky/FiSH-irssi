dnl minimum autoconf version
AC_PREREQ([2.59])
dnl name, version, etc
AC_INIT([libfish], [1.1], [falsovsky@gmail.com], [FiSH irssi module])
dnl file to check if exists
AC_CONFIG_SRCDIR([src/FiSH.c])
dnl file to use for defines
AC_CONFIG_HEADERS([src/config.h])
dnl minimum automake version
AM_INIT_AUTOMAKE([1.9])
dnl directory for m4 macros
AC_CONFIG_MACRO_DIR([m4])

dnl find and test the C compiler
AC_LANG_C
AC_PROG_CC

dnl find and test libtool
AC_PROG_LIBTOOL
AC_SUBST([LIBTOOL_DEPS])

dnl irssi-recode define (maybe remove?)
AC_ARG_ENABLE([irssi-recode], 
    AS_HELP_STRING([--disable-irssi-recode],[disable irssi unicode recode]),
    [AC_DEFINE([FiSH_USE_IRSSI_RECODE], [0], [irssi unicode support])],
    [AC_DEFINE([FiSH_USE_IRSSI_RECODE], [1], [irssi unicode support])]
)

dnl znc-logs define (maybe remove?)
AC_ARG_ENABLE([znc-logs],
    AS_HELP_STRING([--enable-znc-logs],[enable ZNC logs support]),
    [AC_DEFINE([FiSH_DECRYPT_ZNC_LOGS], [1], [ZNC log support])],
    [AC_DEFINE([FiSH_DECRYPT_ZNC_LOGS], [0], [ZNC log support])]
)

dnl irssi source directory
AC_ARG_WITH([irssi-source],
    [AC_HELP_STRING([--with-irssi-source=DIR],
        [irssi source directory]),
    ],
    [IRSSI_PATH=${withval}
        AC_SUBST(IRSSI_PATH)
    ],
    [AC_MSG_ERROR([To build FiSH you will need the irssi source code, please download it and extract it on a desired location.
Then re-run this configure script with --with-irssi-source=/path/to/irssi/source.
eg: ./configure --with-irssi-source=/home/falso/src/irssi-0.8.15])]
)

dnl GMP include directory
AC_ARG_WITH([gmp_include],
    [AC_HELP_STRING([--with-gmp-include=DIR],
        [GMP include directory])
    ],
    [CPPFLAGS="-I$withval $CPPFLAGS"]
)
dnl GML library directory
AC_ARG_WITH([gmp_lib],
    [AC_HELP_STRING([--with-gmp-lib=DIR],
        [GMP library directory])
    ],
    [LDFLAGS="-L$withval $LDFLAGS"]
)
dnl GMP install directory
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
    ]
)

dnl check for glib (using pkg-config)
PKG_CHECK_EXISTS([glib-2.0],
    [
        GLIB_CFLAGS=`pkg-config glib-2.0 --cflags`
        AC_SUBST(GLIB_CFLAGS)
    ],
    [AC_MSG_ERROR([glib-2.0 is not installed])]
)

dnl check for gmp
AC_CHECK_LIB(gmp, __gmpz_init, , [AC_MSG_ERROR(
    [GNU MP not found, see http://swox.com/gmp])]
)

dnl load m4 OpenSSL macro
m4_include([m4/ax_check_openssl.m4])
dnl check for OpenSSL 
PKG_CHECK_MODULES(OPENSSL, [openssl], [], [CHECK_SSL()])

dnl Check if we're a little-endian or a big-endian system
AC_DEFUN([AC_C_ENDIAN],
[AC_CACHE_CHECK(for endianness, ac_cv_c_endian,
[
  AC_RUN_IFELSE(
    [AC_LANG_PROGRAM([], [dnl
        long val = 1;
        char *c = (char *) &val;
        exit(*c == 1);
    ])
  ],[
    ac_cv_c_endian=big
  ],[
    ac_cv_c_endian=little
  ])
])
if test $ac_cv_c_endian = big; then
  AC_DEFINE(ENDIAN_BIG, 1, [machine is bigendian])
fi
if test $ac_cv_c_endian = little; then
  AC_DEFINE(ENDIAN_LITTLE, 1, [machine is littleendian])
fi
])

AC_C_ENDIAN

dnl check size of types
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(long long)
AC_CHECK_SIZEOF(off_t)

dnl UOFF_* required templates
AH_TEMPLATE([PRIuUOFF_T], [printf()-format for uoff_t, eg. "u" or "lu" or "llu"])
AH_TEMPLATE([UOFF_T_INT], [What type should be used for uoff_t])
AH_TEMPLATE([UOFF_T_LONG], [What type should be used for uoff_t])
AH_TEMPLATE([UOFF_T_LONG_LONG], [What type should be used for uoff_t])

dnl various UOFF_* checks
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
    AC_ERROR([Couldnt find integer type for off_t])
fi

dnl define size_t to a suitable type
AC_TYPE_SIZE_T

dnl check for GNU C library compatible malloc
AC_FUNC_MALLOC

dnl check for stdio.h functions
AC_CHECK_FUNCS([fopen fread fclose fgets feof remove rename sprintf snprintf fprintf])

dnl check for stdlib.h/misc functions
AC_CHECK_FUNCS([free getpass])

dnl check for string.h functions
AC_CHECK_FUNCS([strncpy strlen strcpy strncmp strcat strcmp strstr strchr strtok strspn strncasecmp strcasecmp memmove memset])

dnl define project Makefiles
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])

dnl finish him!
AC_OUTPUT
