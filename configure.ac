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

#
# check for functions
#
AC_C_CONST
AC_CHECK_FUNCS([getpass getpassphrase memset])
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_FUNC_VPRINTF
AC_REPLACE_FUNCS(strlcpy)
AC_REPLACE_FUNCS(strlcat)
AC_STRUCT_TM
AC_TYPE_SIZE_T

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([limits.h stdint.h stdlib.h string.h strings.h sys/socket.h unistd.h])


# Check for explicit PKCS11 modules
ACX_PKCS11_MODULES

# Expand some variables
full_localstatedir=`eval eval eval eval eval echo "${localstatedir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`

opendnsseclocalstatedir=$full_localstatedir/opendnssec
opendnssecsysconfdir=$full_sysconfdir/opendnssec

AC_SUBST([opendnsseclocalstatedir])
AC_SUBST([opendnssecsysconfdir])

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

# Set up the default configuration file location
conf_file_dir=$sysconfdir/opendnssec
AC_DEFINE_UNQUOTED(CONFIGDIR, ["`eval echo $conf_file_dir | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC configuration files])

open_var_dir="$prefix/var/opendnssec"
AC_DEFINE_UNQUOTED(VAR_DIR, ["`eval echo $open_var_dir | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC var directory])

signer_cli="$prefix/bin/signer_engine_cli update"
AC_DEFINE_UNQUOTED(SIGNER_CLI, ["`eval echo $signer_cli | sed s,NONE,$ac_default_prefix,g`"], [Path to the OpenDNSSEC signer engine cli])




dnl AC_CONFIG_SUBDIRS([softHSM])

AH_BOTTOM([
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif           
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif
])

AC_CONFIG_HEADER([libksm/src/include/ksm/config.h])

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
])

AC_OUTPUT
