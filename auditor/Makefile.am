# $Id: Makefile.am 1104 2009-06-24 07:28:23Z jakob $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

EXTRA_DIST = \
	$(srcdir)/lib/*.rb \
	$(srcdir)/lib/kasp_auditor/*.rb

bin_SCRIPTS = kasp_auditor

install-data-hook:
	${INSTALL} -d -m 755 $(opendnsseclibdir)
	${INSTALL} -d -m 755 $(opendnsseclibdir)/kasp_auditor
	${INSTALL_DATA} $(srcdir)/lib/*.rb $(opendnsseclibdir)
	${INSTALL_DATA} $(srcdir)/lib/kasp_auditor/*.rb $(opendnsseclibdir)/kasp_auditor
