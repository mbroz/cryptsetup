SUBDIRS = crypto_backend luks1 loopaes

moduledir = $(libdir)/cryptsetup

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcryptsetup.pc

INCLUDES = \
	-I$(top_srcdir)				\
	-I$(top_srcdir)/lib/crypto_backend	\
	-I$(top_srcdir)/lib/luks1		\
	-I$(top_srcdir)/lib/loopaes		\
	-DDATADIR=\""$(datadir)"\"		\
	-DLIBDIR=\""$(libdir)"\"		\
	-DPREFIX=\""$(prefix)"\"		\
	-DSYSCONFDIR=\""$(sysconfdir)"\"	\
	-DVERSION=\""$(VERSION)"\"		\
	-D_GNU_SOURCE				\
	-D_LARGEFILE64_SOURCE			\
	-D_FILE_OFFSET_BITS=64

lib_LTLIBRARIES = libcryptsetup.la

common_ldadd = \
	crypto_backend/libcrypto_backend.la	\
	luks1/libluks1.la			\
	loopaes/libloopaes.la

libcryptsetup_la_DEPENDENCIES = $(common_ldadd) libcryptsetup.sym

libcryptsetup_la_LDFLAGS = \
	-Wl,--version-script=$(top_srcdir)/lib/libcryptsetup.sym \
	-version-info @LIBCRYPTSETUP_VERSION_INFO@

libcryptsetup_la_CFLAGS = -Wall @CRYPTO_CFLAGS@

libcryptsetup_la_LIBADD = \
	@UUID_LIBS@				\
	@DEVMAPPER_LIBS@			\
	@CRYPTO_LIBS@				\
	@FIPSCHECK_LIBS@			\
	$(common_ldadd)


libcryptsetup_la_SOURCES = \
	setup.c					\
	internal.h				\
	nls.h					\
	libcryptsetup.h				\
	utils.c					\
	utils_crypt.c				\
	utils_crypt.h				\
	utils_debug.c				\
	utils_loop.c				\
	utils_loop.h				\
	utils_devpath.c				\
	utils_wipe.c				\
	utils_fips.c				\
	utils_fips.h				\
	libdevmapper.c				\
	utils_dm.h				\
	volumekey.c				\
	random.c				\
	crypt_plain.c

include_HEADERS = libcryptsetup.h

EXTRA_DIST = libcryptsetup.pc.in libcryptsetup.sym
