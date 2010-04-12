# $Id$
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

m4_sinclude([version.m4])

AC_PREREQ([2.61])
AC_INIT([ods-signer], OPENDNSSEC_VERSION)

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

OPENDNSSEC_COMMON

AC_CHECK_HEADERS(getopt.h,, [AC_INCLUDES_DEFAULT])

CHECK_COMPILER_FLAG(std=c99, [C99FLAG="-std=c99"])
CHECK_COMPILER_FLAG(xc99, [C99FLAG="-xc99"])
CHECK_COMPILER_FLAG_NEEDED($C99FLAG, [#include <stdbool.h>], [CFLAGS="$CFLAGS $C99FLAG"])

CHECK_COMPILER_FLAG_NEEDED(-D__EXTENSIONS__,
[
#include "confdefs.h"
#include <stdlib.h>
#include <unistd.h>

int test() {
	int a;
	char **opts = NULL;
	a = getopt(2, opts, "a");
	return a;
}
], [CFLAGS="-D__EXTENSIONS__ $CFLAGS"])

# check if setreuid en setregid fail, on MacOSX10.4(darwin8).
if echo $build_os | grep darwin8 > /dev/null; then
    AC_DEFINE(DARWIN_BROKEN_SETREUID, 1, [Define this if on macOSX10.4-darwin8 and setreuid and setregid do not work])
fi

ACX_PEDANTIC
ACX_STRICT
ACX_BROKEN_SETRES

# Check for some target-specific stuff
case "$host" in
*-*-darwin*)
    AC_DEFINE(SETEUID_BREAKS_SETUID, 1,
        [Define if your platform breaks doing a seteuid before a setuid])
    AC_DEFINE(BROKEN_SETREUID, 1, [Define if your setreuid() is broken])
    AC_DEFINE(BROKEN_SETREGID, 1, [Define if your setregid() is broken])
    ;;
esac

ACX_LDNS(1,6,4)
ACX_LIBXML2
ACX_LIBHSM

AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([src/config.h])
AC_PROG_INSTALL
AC_PROG_LIBTOOL

AC_DEFINE_UNQUOTED(ODS_SE_PIDFILE, ["$OPENDNSSEC_SIGNER_PIDFILE"], [Path to the OpenDNSSEC signer engine pid file])
AC_DEFINE_UNQUOTED(ODS_SE_CFGFILE, ["$OPENDNSSEC_CONFIG_FILE"], [Path to the OpenDNSSEC config file])

AC_CHECK_FUNCS([arc4random arc4random_uniform])

# Checks for header files.
AC_CHECK_HEADERS([getopt.h stdio.h stdlib.h])

AC_CONFIG_FILES([
	Makefile
])

AC_OUTPUT
