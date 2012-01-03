AC_PREREQ([2.65])
AC_INIT([libfish], [1.0], [falsovsky@gmail.com], [FiSH irssi module])
AC_CONFIG_SRCDIR([FiSH.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB

AM_INIT_AUTOMAKE([1.9])

AC_LANG([C])

# Checks for libraries.
AC_CHECK_LIB(gmp, __gmpz_init, , [AC_MSG_ERROR(
    [GNU MP not found, see http://swox.com/gmp])])

# Checks for header files.
AC_CHECK_HEADERS([stddef.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([getpass memmove memset strcasecmp strchr strncasecmp strrchr strspn strstr])

AC_SUBST([AM_CXXFLAGS])
AC_SUBST([AM_LDFLAGS])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
