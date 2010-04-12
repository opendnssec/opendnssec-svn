# $Id$

AM_CPPFLAGS = @LIBHSM_INCLUDES@ @LDNS_INCLUDES@ @XML2_INCLUDES@

ACLOCAL_AMFLAGS = -I m4

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ \
	$(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/aclocal.m4 $(srcdir)/compile \
	$(srcdir)/config.guess $(srcdir)/config.sub

signerdir =     @libdir@/opendnssec/signer

signer_PROGRAMS = \
	ods_signerd

# man8_MANS =     man/ods-signer.8 man/ods-signerd.8

ods_signerd_SOURCES=		src/ods-signerd.c
ods_signerd_LDADD=		@LDNS_LIBS@ @XML2_LIBS@ @LIBHSM_LIBS@
ods_signerd_DEPENDENCIES=	@BUILD_LIBHSM@

EXTRA_DIST = $(srcdir)/*.h

../libhsm/src/libhsm.la:
	(cd ../libhsm/src; ${MAKE} libhsm.la)

# TODO: move this to general opendnssec install
install-data-hook:
	$(INSTALL) -d $(DESTDIR)$(localstatedir)
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/tmp
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/signconf
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/unsigned
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/opendnssec/signed
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/run
	$(INSTALL) -d $(DESTDIR)$(localstatedir)/run/opendnssec
