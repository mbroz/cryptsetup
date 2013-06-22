SUBDIRS = crypto_backend luks1 loopaes verity tcrypt

moduledir = $(libdir)/cryptsetup

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcryptsetup.pc

AM_CPPFLAGS = -include config.h \
	-I$(top_srcdir)				\
	-I$(top_srcdir)/lib/crypto_backend	\
	-I$(top_srcdir)/lib/luks1		\
	-I$(top_srcdir)/lib/loopaes		\
	-I$(top_srcdir)/lib/verity		\
	-I$(top_srcdir)/lib/tcrypt		\
	-DDATADIR=\""$(datadir)"\"		\
	-DLIBDIR=\""$(libdir)"\"		\
	-DPREFIX=\""$(prefix)"\"		\
	-DSYSCONFDIR=\""$(sysconfdir)"\"	\
	-DVERSION=\""$(VERSION)"\"

lib_LTLIBRARIES = libcryptsetup.la

common_ldadd = \
	crypto_backend/libcrypto_backend.la	\
	luks1/libluks1.la			\
	loopaes/libloopaes.la			\
	verity/libverity.la			\
	tcrypt/libtcrypt.la

libcryptsetup_la_DEPENDENCIES = $(common_ldadd) libcryptsetup.sym

libcryptsetup_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined \
	-Wl,--version-script=$(top_srcdir)/lib/libcryptsetup.sym \
	-version-info @LIBCRYPTSETUP_VERSION_INFO@

libcryptsetup_la_CFLAGS = -Wall $(AM_CFLAGS) @CRYPTO_CFLAGS@

libcryptsetup_la_LIBADD = \
	@UUID_LIBS@				\
	@DEVMAPPER_LIBS@			\
	@CRYPTO_LIBS@				\
	@FIPSCHECK_LIBS@			\
	$(common_ldadd)


libcryptsetup_la_SOURCES = \
	setup.c					\
	internal.h				\
	bitops.h				\
	nls.h					\
	libcryptsetup.h				\
	utils.c					\
	utils_benchmark.c			\
	utils_crypt.c				\
	utils_crypt.h				\
	utils_loop.c				\
	utils_loop.h				\
	utils_devpath.c				\
	utils_wipe.c				\
	utils_fips.c				\
	utils_fips.h				\
	utils_device.c				\
	libdevmapper.c				\
	utils_dm.h				\
	volumekey.c				\
	random.c				\
	crypt_plain.c

include_HEADERS = libcryptsetup.h

EXTRA_DIST = libcryptsetup.pc.in libcryptsetup.sym
