# $Id: Makefile.am 4052 2010-10-05 12:43:57Z matthijs $

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

LIBHSM = ${top_builddir}/libhsm/src/libhsm.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/common \
	-I$(top_builddir)/common \
	-I$(srcdir)/../../libhsm/src \
	-I$(builddir)/../../libhsm/src \
	@XML2_INCLUDES@ \
	@LDNS_INCLUDES@

signerdir =     @libdir@/opendnssec/signer

sbin_PROGRAMS = ods-signerd ods-signer

ods_signerd_SOURCES=		ods-signerd.c \
				adapter/adapter.c adapter/adapter.h \
				daemon/cfg.c daemon/cfg.h \
				daemon/cmdhandler.c daemon/cmdhandler.h \
				daemon/engine.c daemon/engine.h \
				daemon/signal.c daemon/signal.h \
				daemon/worker.c daemon/worker.h \
				parser/confparser.c parser/confparser.h \
				parser/signconfparser.c parser/signconfparser.h \
				parser/zonelistparser.c parser/zonelistparser.h \
				scheduler/schedule.c scheduler/schedule.h \
				scheduler/task.c scheduler/task.h \
				shared/allocator.c shared/allocator.h \
				shared/duration.c shared/duration.h \
				shared/file.c shared/file.h \
				shared/locks.c shared/locks.h \
				shared/log.c shared/log.h \
				shared/privdrop.c shared/privdrop.h \
				shared/status.c shared/status.h \
				shared/util.c shared/util.h \
				signer/keys.c signer/keys.h \
				signer/signconf.c signer/signconf.h \
				signer/zone.c signer/zone.h \
				signer/zonelist.c signer/zonelist.h

ods_signerd_LDADD=		$(LIBHSM)
ods_signerd_LDADD+=		@LDNS_LIBS@ @XML2_LIBS@ @PTHREAD_LIBS@ @RT_LIBS@

ods_signer_SOURCES=		ods-signer.c \
				shared/allocator.c shared/allocator.h \
				shared/duration.c shared/duration.h \
				shared/file.c shared/file.h \
				shared/log.c shared/log.h \
				shared/util.c shared/util.h

ods_signer_LDADD=		$(LIBHSM)
ods_signer_LDADD+=		@LDNS_LIBS@ @XML2_LIBS@
