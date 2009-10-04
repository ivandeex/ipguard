#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([ipguard], [0.4], [rpmadminATvitki.net])

AC_CONFIG_SRCDIR([ipguard.h])
AC_PROG_LIBTOOL
AM_MAINTAINER_MODE
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)

AC_CONFIG_HEADERS([config.h:config.in])

AC_PROG_CC
AC_PROG_LD
AC_PROG_INSTALL

AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)

# Checks for header files.
AC_CHECK_HEADERS([regex.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_PID_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([regcomp])

AC_CONFIG_FILES([Makefile etc/Makefile])
AC_OUTPUT

