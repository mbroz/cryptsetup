INCLUDES = \
	-I$(top_srcdir)				\
	-I$(top_srcdir)/lib			\
	-DDATADIR=\""$(datadir)"\"		\
	-DLOCALEDIR=\""$(datadir)/locale"\"	\
	-DLIBDIR=\""$(libdir)"\"		\
	-DPREFIX=\""$(prefix)"\"		\
	-DSYSCONFDIR=\""$(sysconfdir)"\"	\
	-DVERSION=\""$(VERSION)"\"		\
	-D_GNU_SOURCE

cryptsetup_SOURCES = \
	$(top_builddir)/lib/utils_crypt.c	\
	$(top_builddir)/lib/utils_loop.c	\
	$(top_builddir)/lib/utils_fips.c	\
	cryptsetup.c				\
	cryptsetup.h

cryptsetup_LDADD = \
	$(top_builddir)/lib/libcryptsetup.la	\
	@POPT_LIBS@				\
	@FIPSCHECK_LIBS@

cryptsetup_CFLAGS = -Wall

sbin_PROGRAMS=cryptsetup

if STATIC_CRYPTSETUP
sbin_PROGRAMS += cryptsetup.static
cryptsetup_static_SOURCES = $(cryptsetup_SOURCES)
cryptsetup_static_CFLAGS = $(cryptsetup_CFLAGS)
cryptsetup_static_LDFLAGS = -all-static
cryptsetup_static_LDADD = $(cryptsetup_LDADD)	\
	@CRYPTO_STATIC_LIBS@			\
	@DEVMAPPER_STATIC_LIBS@			\
	@UUID_LIBS@
endif
