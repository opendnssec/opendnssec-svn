# $Id: configure.ac 1335 2009-07-20 22:37:56Z jelte $

AC_PREREQ(2.61)
AC_INIT([opendnssec], [0.0.1], [])

AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)

# Checks for programs
AC_PATH_PROG(XMLLINT, xmllint)
AC_PATH_PROG(JAVA, java)
ACX_TRANG

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
])

AC_OUTPUT
