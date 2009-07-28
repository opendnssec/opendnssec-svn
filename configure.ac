# $Id: configure.ac 1335 2009-07-20 22:37:56Z jelte $

AC_PREREQ(2.61)
AC_INIT([opendnssec], [0.0.1], [])

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

ACX_ARG_RPATH
ACX_RUNTIME_PATH_ADD

ACX_PEDANTIC
ACX_STRICT

#
# Checks for programs
#

# xml
AC_PATH_PROG(XMLLINT, xmllint)
AC_PATH_PROG(JAVA, java)
ACX_TRANG

# libhsm
ACX_LIBXML2
ACX_LDNS
ACX_DLOPEN

# libksm
AC_PATH_PROG(PERL, perl)
if test -z "$PERL"; then
   AC_MSG_ERROR([perl not found])
fi
ACX_CUNIT
ACX_SQLITE3

# signer
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(nsl, inet_pton)
AM_PATH_PYTHON

# auditor
AM_PATH_RUBY([], [], [])


#
# check for functions
#
AC_C_CONST
AC_CHECK_FUNCS([dup2 endpwent memset getpass getpassphrase select strerror strtol])
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_VPRINTF
AC_HEADER_STDBOOL
AC_REPLACE_FUNCS(strlcpy)
AC_REPLACE_FUNCS(strlcat)
AC_STRUCT_TM
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h getopt.h inttypes.h limits.h stdint.h stdio.h])
AC_CHECK_HEADERS([stdlib.h string.h strings.h sys/socket.h syslog.h])
AC_CHECK_HEADERS([unistd.h])


# Check for explicit PKCS11 modules
ACX_PKCS11_MODULES

# Expand some variables
full_localstatedir=`eval eval eval eval eval echo "${localstatedir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_libdir=`eval eval eval eval eval echo "${libdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_libexecdir=`eval eval eval eval eval echo "${libexecdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`

opendnsseclocalstatedir=$full_localstatedir/opendnssec
opendnssecsysconfdir=$full_sysconfdir/opendnssec
opendnsseclibdir=$full_libdir/opendnssec
opendnsseclibexecdir=$full_libexecdir/opendnssec

AC_SUBST([opendnsseclocalstatedir])
AC_SUBST([opendnssecsysconfdir])
AC_SUBST([opendnsseclibdir])
AC_SUBST([opendnsseclibexecdir])

#
# module specifics
#

# libksm
# for now, only SQLite3 is supported
DB_INCLUDES=$SQLITE3_INCLUDES
DB_LIBS=$SQLITE3_LIBS
DB_TYPE=sqlite3
AC_DEFINE_UNQUOTED(SQL_BIN, "$SQLITE3", [database binary])
AC_DEFINE_UNQUOTED(SQL_SETUP, "$prefix/share/opendnssec/database_create.sqlite3", [database setup script])

AC_SUBST(DB_INCLUDES)
AC_SUBST(DB_LIBS)
AC_SUBST(DB_TYPE)

AC_ARG_WITH(dbname,
[  --with-dbname=DB_NAME   Database name/schema for unit tests  ],
   DB_NAME="$withval"
)
AC_SUBST(DB_NAME)

AC_ARG_WITH(dbhost,
[  --with-dbhost=DB_HOST   Database host for unit tests  ],
   DB_HOST="$withval"
)
AC_SUBST(DB_HOST)

AC_ARG_WITH(dbpass,
[  --with-dbpass=DB_PASS   Database host for unit tests  ],
   DB_PASS="$withval"
)
AC_SUBST(DB_PASS)

AC_ARG_WITH(dbuser,
[  --with-dbuser=DB_USER   Database host for unit tests  ],
   DB_USER="$withval"
)
AC_SUBST(DB_USER)

opendnssecsysconf="\$(sysconfdir)/opendnssec"
ksmdatadir="\$(datadir)/opendnssec"
ksmincludedir="\$(includedir)/ksm"

AC_SUBST([opendnssecsysconf])
AC_SUBST([ksmdatadir])
AC_SUBST([ksmincludedir])

# enforcer
keygend_conf_file=$sysconfdir/opendnssec/conf.xml
AC_DEFINE_UNQUOTED(CONFIGFILE, ["`eval echo $keygend_conf_file | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC configuration file])
keygend_conf_schema=$sysconfdir/opendnssec/conf.rng
AC_DEFINE_UNQUOTED(CONFIGRNG, ["`eval echo $keygend_conf_schema  | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC configuration schema file])
com_pid_file=$localstatedir/run/opendnssec/communicated.pid
AC_DEFINE_UNQUOTED(COM_PID, ["`eval echo $com_pid_file | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC communicated pid file])
keygen_pid_file=$localstatedir/run/opendnssec/keygend.pid
AC_DEFINE_UNQUOTED(KEYGEN_PID, ["`eval echo $keygen_pid_file | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC keygend pid file])

# signer
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


# auditor
AC_MSG_CHECKING([for ruby library rubygems])
have_ruby_rubygems=`$RUBY -e 'require "rubygems"; print "yes"'`
if test "x$have_ruby_rubygems" = "x"; then
    AC_MSG_ERROR([Missing ruby library rubygems])
fi
AC_MSG_RESULT([yes])

AC_MSG_CHECKING([for ruby library syslog])
have_ruby_syslog=`$RUBY -e 'require "syslog"; print "yes"'`
if test "x$have_ruby_syslog" = "x"; then
    AC_MSG_ERROR([Missing ruby library syslog])
fi
AC_MSG_RESULT([yes])

AC_MSG_CHECKING([for ruby library openssl])
have_ruby_openssl=`$RUBY -e 'require "openssl"; print "yes"'`
if test "x$have_ruby_openssl" = "x"; then
    AC_MSG_ERROR([Missing ruby library openssl])
fi
AC_MSG_RESULT([yes])

AC_MSG_CHECKING([for ruby library dnsruby])
have_ruby_dnsruby=`$RUBY -e 'require "rubygems"; require "dnsruby"; print "yes"'`
if test "x$have_ruby_dnsruby" = "x"; then
    AC_MSG_ERROR([Missing ruby library dnsruby])
fi
AC_MSG_RESULT([yes])

AC_MSG_CHECKING([for ruby library xsd/datatypes])
have_ruby_xsd_datatypes=`$RUBY -e 'require "xsd/datatypes"; print "yes"'`
if test "x$have_ruby_xsd_datatypes" = "x"; then
    AC_MSG_ERROR([Missing ruby library xsd/datatypes])
fi
AC_MSG_RESULT([yes])

AC_MSG_CHECKING([for ruby library rexml/document])
have_ruby_rexml_document=`$RUBY -e 'require "rexml/document"; print "yes"'`
if test "x$have_ruby_rexml_document" = "x"; then
    AC_MSG_ERROR([Missing ruby library rexml/document])
fi
AC_MSG_RESULT([yes])



# shared

# Set up the default configuration file location
conf_file_dir=$sysconfdir/opendnssec
AC_DEFINE_UNQUOTED(CONFIGDIR, ["`eval echo $conf_file_dir | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC configuration files])

open_var_dir="$prefix/var/opendnssec"
AC_DEFINE_UNQUOTED(VAR_DIR, ["`eval echo $open_var_dir | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC var directory])

signer_cli="$prefix/bin/signer_engine_cli update"
AC_DEFINE_UNQUOTED(SIGNER_CLI, ["`eval echo $signer_cli | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC signer engine cli])



AC_CONFIG_SUBDIRS([softHSM])

AH_BOTTOM([
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif           
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif
])

AC_CONFIG_SRCDIR([enforcer/common/daemon.h])
AC_CONFIG_HEADER([libksm/src/include/ksm/config.h])
AC_CONFIG_HEADER([signer/tools/config.h])
AC_CONFIG_HEADER([enforcer/config.h])

AC_CONFIG_FILES([
	Makefile
	xml/Makefile
	xml/conf.xml
	xml/kasp.xml
	xml/signconf.xml
	xml/zonelist.xml
	libhsm/Makefile
	libhsm/src/Makefile
	libhsm/checks/Makefile
	libhsm/checks/conf-softhsm.xml
	libhsm/checks/conf-sca6000.xml
	libhsm/checks/conf-etoken.xml
	libhsm/checks/conf-multi.xml
	libhsm/checks/conf-opensc.xml
	libksm/Makefile
	libksm/src/Makefile
	libksm/src/include/Makefile
	libksm/src/include/ksm/Makefile
	libksm/utils/Makefile
	libksm/test/Makefile
	enforcer/Makefile
	enforcer/common/Makefile
	enforcer/communicated/Makefile
	enforcer/keygend/Makefile
	signer/Makefile
	signer/tools/Makefile
	signer/signer_engine/Makefile
	signer/signer_engine/signer_engine
	signer/signer_engine/EngineConfig.py
	signer/signer_engine/signer_engine_cli
	auditor/Makefile
	auditor/kasp_auditor
])

AC_OUTPUT
