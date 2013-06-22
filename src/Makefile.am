AM_CPPFLAGS = -include config.h \
	-I$(top_srcdir)				\
	-I$(top_srcdir)/lib			\
	-DDATADIR=\""$(datadir)"\"		\
	-DLOCALEDIR=\""$(datadir)/locale"\"	\
	-DLIBDIR=\""$(libdir)"\"		\
	-DPREFIX=\""$(prefix)"\"		\
	-DSYSCONFDIR=\""$(sysconfdir)"\"	\
	-DVERSION=\""$(VERSION)"\"

# cryptsetup
cryptsetup_SOURCES = \
	$(top_builddir)/lib/utils_crypt.c	\
	$(top_builddir)/lib/utils_loop.c	\
	$(top_builddir)/lib/utils_fips.c	\
	utils_tools.c				\
	utils_password.c			\
	cryptsetup.c				\
	cryptsetup.h

cryptsetup_LDADD = \
	$(top_builddir)/lib/libcryptsetup.la	\
	@POPT_LIBS@				\
	@FIPSCHECK_LIBS@			\
	@PWQUALITY_LIBS@

cryptsetup_CFLAGS = $(AM_CFLAGS) -Wall

sbin_PROGRAMS=cryptsetup

if STATIC_TOOLS
sbin_PROGRAMS += cryptsetup.static
cryptsetup_static_SOURCES = $(cryptsetup_SOURCES)
cryptsetup_static_CFLAGS = $(cryptsetup_CFLAGS)
cryptsetup_static_LDFLAGS = $(AM_LDFLAGS) -all-static
cryptsetup_static_LDADD = $(cryptsetup_LDADD)	\
	@CRYPTO_STATIC_LIBS@			\
	@PWQUALITY_STATIC_LIBS@			\
	@DEVMAPPER_STATIC_LIBS@			\
	@UUID_LIBS@
endif

# veritysetup
if VERITYSETUP

veritysetup_SOURCES = \
	$(top_builddir)/lib/utils_crypt.c	\
	$(top_builddir)/lib/utils_loop.c	\
	utils_tools.c				\
	veritysetup.c				\
	cryptsetup.h

veritysetup_LDADD = \
	$(top_builddir)/lib/libcryptsetup.la	\
	@POPT_LIBS@

veritysetup_CFLAGS = $(cryptsetup_CFLAGS)

sbin_PROGRAMS += veritysetup

if STATIC_TOOLS
sbin_PROGRAMS += veritysetup.static
veritysetup_static_SOURCES = $(veritysetup_SOURCES)
veritysetup_static_CFLAGS = $(veritysetup_CFLAGS)
veritysetup_static_LDFLAGS = $(AM_LDFLAGS) -all-static
veritysetup_static_LDADD = $(veritysetup_LDADD)	\
	@CRYPTO_STATIC_LIBS@ \
	@DEVMAPPER_STATIC_LIBS@ \
	@UUID_LIBS@
endif
endif

# reencrypt
if REENCRYPT
cryptsetup_reencrypt_SOURCES = \
	$(top_builddir)/lib/utils_crypt.c	\
	utils_tools.c				\
	cryptsetup_reencrypt.c			\
	cryptsetup.h

cryptsetup_reencrypt_LDADD = $(cryptsetup_LDADD)
cryptsetup_reencrypt_CFLAGS = $(cryptsetup_CFLAGS)

sbin_PROGRAMS += cryptsetup-reencrypt

if STATIC_TOOLS
sbin_PROGRAMS += cryptsetup-reencrypt.static
cryptsetup_reencrypt_static_SOURCES = $(cryptsetup_reencrypt_SOURCES)
cryptsetup_reencrypt_static_CFLAGS = $(cryptsetup_reencrypt_CFLAGS)
cryptsetup_reencrypt_static_LDFLAGS = $(AM_LDFLAGS) -all-static
cryptsetup_reencrypt_static_LDADD = $(cryptsetup_reencrypt_LDADD)	\
	@CRYPTO_STATIC_LIBS@ \
	@DEVMAPPER_STATIC_LIBS@ \
	@UUID_LIBS@
endif
endif
