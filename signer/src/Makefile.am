# $Id$

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = @LIBHSM_INCLUDES@ @LDNS_INCLUDES@ @XML2_INCLUDES@

signerdir =     @libdir@/opendnssec/signer

sbin_PROGRAMS = ods-signerd ods-signer
# man8_MANS =     man/ods-signer.8 man/ods-signerd.8

ods_signerd_SOURCES=		ods-signerd.c \
				adapter/adapter.c adapter/adapter.h \
				daemon/cmdhandler.c daemon/cmdhandler.h \
				daemon/config.c daemon/config.h \
				daemon/engine.c daemon/engine.h \
				daemon/signal.c daemon/signal.h \
				parser/confparser.c parser/confparser.h \
				scheduler/locks.c scheduler/locks.h \
				signer/domain.c signer/domain.h \
				signer/zone.c signer/zone.h \
				signer/zonedata.c signer/zonedata.h \
				signer/zonelist.c signer/zonelist.h \
				util/file.c util/file.h \
				util/log.c util/log.h \
				util/privdrop.c util/privdrop.h \
				util/se_malloc.c util/se_malloc.h

ods_signerd_LDADD=		@LDNS_LIBS@ @XML2_LIBS@ @LIBHSM_LIBS@ @PTHREAD_LIBS@
ods_signerd_DEPENDENCIES=	@BUILD_LIBHSM@

ods_signer_SOURCES=		ods-signer.c \
				util/file.c util/file.h \
				util/log.c util/log.h \
				util/se_malloc.c util/se_malloc.h

ods_signer_LDADD=		@LDNS_LIBS@ @XML2_LIBS@ @LIBHSM_LIBS@
ods_signer_DEPENDENCIES=

EXTRA_DIST = $(srcdir)/*.h

../../libhsm/src/libhsm.la:
	(cd ../../libhsm/src; ${MAKE} libhsm.la)
