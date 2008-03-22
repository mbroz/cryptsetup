moduledir = $(libdir)/cryptsetup

if BUILD_LIBDEVMAPPER
_LIBDEVMAPPER_LIBADD = @LIBDEVMAPPER_LIBS@
_LIBDEVMAPPER_SOURCES = libdevmapper.c
_LIBDEVMAPPER_CFLAGS = -DBUILTIN_LIBDEVMAPPER
endif
libbbackend_devmapper_la_SOURCES = libdevmapper.c
libbbackend_devmapper_la_LDFLAGS = -avoid-version -module
libbbackend_devmapper_la_LIBADD = @LIBDEVMAPPER_LIBS@
if SHARED_LIBDEVMAPPER
_LIBDEVMAPPER_SHLIB = libbbackend_devmapper.la
endif

if BUILD_LIBGCRYPT
_LIBGCRYPT_LIBADD = @LIBGCRYPT_LIBS@
_LIBGCRYPT_SOURCES = gcrypt.c
_LIBGCRYPT_CFLAGS = -DBUILTIN_GCRYPT
endif
libcrypto_gcrypt_la_SOURCES = gcrypt.c
libcrypto_gcrypt_la_LDFLAGS = -avoid-version -module
libcrypto_gcrypt_la_LIBADD = @LIBGCRYPT_LIBS@
if SHARED_LIBGCRYPT
_LIBGCRYPT_SHLIB = libcrypto_gcrypt.la
endif

INCLUDES = \
	-I$(top_srcdir)				\
	-I$(top_srcdir)/luks			\
	-DDATADIR=\""$(datadir)"\"		\
	-DLIBDIR=\""$(libdir)"\"		\
	-DPREFIX=\""$(prefix)"\"		\
	-DSYSCONFDIR=\""$(sysconfdir)"\"	\
	-DVERSION=\""$(VERSION)"\"		\
	-D_GNU_SOURCE				\
	-D_LARGEFILE64_SOURCE			\
	-D_FILE_OFFSET_BITS=64			\
	@LIBDEVMAPPER_CFLAGS@			\
	$(_LIBDEVMAPPER_CFLAGS)			\
	@LIBGCRYPT_CFLAGS@			\
	$(_LIBGCRYPT_CFLAGS)

lib_LTLIBRARIES = \
	libcryptsetup.la

module_LTLIBRARIES = \
	$(_LIBDEVMAPPER_SHLIB)			\
	$(_LIBGCRYPT_SHLIB)

if STATIC_LIBRARY
_STATIC_LIBRARY = -static
endif

libcryptsetup_la_LDFLAGS = \
	$(_STATIC_LIBRARY)

libcryptsetup_la_LIBADD = \
	$(_LIBDEVMAPPER_LIBADD)			\
	$(_LIBGCRYPT_LIBADD)			\
	@UUID_LIBS@				\
	../luks/libluks.la

libcryptsetup_la_SOURCES = \
	setup.c					\
	internal.h				\
	blockdev.h				\
	libcryptsetup.h				\
	utils.c					\
	backends.c				\
	$(_LIBDEVMAPPER_SOURCES)		\
	$(_LIBGCRYPT_SOURCES)

include_HEADERS = \
	libcryptsetup.h
