moduledir = $(libdir)/cryptsetup

noinst_LTLIBRARIES = libcrypto_backend.la

libcrypto_backend_la_CFLAGS = $(AM_CFLAGS) -Wall @CRYPTO_CFLAGS@

libcrypto_backend_la_SOURCES = crypto_backend.h \
	crypto_cipher_kernel.c crypto_storage.c pbkdf_check.c crc32.c

if CRYPTO_BACKEND_GCRYPT
libcrypto_backend_la_SOURCES += crypto_gcrypt.c
endif
if CRYPTO_BACKEND_OPENSSL
libcrypto_backend_la_SOURCES += crypto_openssl.c
endif
if CRYPTO_BACKEND_NSS
libcrypto_backend_la_SOURCES += crypto_nss.c
endif
if CRYPTO_BACKEND_KERNEL
libcrypto_backend_la_SOURCES += crypto_kernel.c
endif
if CRYPTO_BACKEND_NETTLE
libcrypto_backend_la_SOURCES += crypto_nettle.c
endif

if CRYPTO_INTERNAL_PBKDF2
libcrypto_backend_la_SOURCES += pbkdf2_generic.c
endif

AM_CPPFLAGS = -include config.h -I$(top_srcdir)/lib
