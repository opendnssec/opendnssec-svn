# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = @LIBHSM_INCLUDES@ @LDNS_INCLUDES@ @XML2_INCLUDES@

signerdir =     @libdir@/opendnssec/signer

sbin_PROGRAMS = ods-signerd
# man8_MANS =     man/ods-signer.8 man/ods-signerd.8

ods_signerd_SOURCES=		ods-signerd.c \
				daemon/cmdhandler.c daemon/cmdhandler.h \
				daemon/config.c daemon/config.h \
				daemon/engine.c daemon/engine.h \
				parser/confparser.c parser/confparser.h \
				scheduler/locks.c scheduler/locks.h \
				util/file.c util/file.h \
				util/log.c util/log.h \
				util/se_malloc.c util/se_malloc.h

ods_signerd_LDADD=		@LDNS_LIBS@ @XML2_LIBS@ @LIBHSM_LIBS@ @PTHREAD_LIBS@
ods_signerd_DEPENDENCIES=	@BUILD_LIBHSM@

EXTRA_DIST = $(srcdir)/*.h

../../libhsm/src/libhsm.la:
	(cd ../../libhsm/src; ${MAKE} libhsm.la)
