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

# Checks for programs

# xml
AC_PATH_PROG(XMLLINT, xmllint)
AC_PATH_PROG(JAVA, java)
ACX_TRANG

# libhsm
ACX_LIBXML2
ACX_LDNS
ACX_DLOPEN

# check for functions
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([getpass getpassphrase memset])
AC_REPLACE_FUNCS(strlcpy)
AC_REPLACE_FUNCS(strlcat)


# Check for explicit PKCS11 modules
ACX_PKCS11_MODULES

# Expand some variables
full_localstatedir=`eval eval eval eval eval echo "${localstatedir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`
full_sysconfdir=`eval eval eval eval eval echo "${sysconfdir}" | sed "s#NONE#${prefix}#" | sed "s#NONE#${ac_default_prefix}#"`

opendnsseclocalstatedir=$full_localstatedir/opendnssec
opendnssecsysconfdir=$full_sysconfdir/opendnssec

AC_SUBST([opendnsseclocalstatedir])
AC_SUBST([opendnssecsysconfdir])


dnl AC_CONFIG_SUBDIRS([softHSM])

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
])

AC_OUTPUT([
	libhsm/checks/conf-softhsm.xml
	libhsm/checks/conf-sca6000.xml
	libhsm/checks/conf-etoken.xml
	libhsm/checks/conf-multi.xml
	libhsm/checks/conf-opensc.xml
])
