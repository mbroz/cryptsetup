moduledir = $(libdir)/cryptsetup

noinst_LTLIBRARIES = libtcrypt.la

libtcrypt_la_CFLAGS = -Wall @CRYPTO_CFLAGS@

libtcrypt_la_SOURCES = \
	tcrypt.c \
	tcrypt.h

AM_CPPFLAGS = -D_GNU_SOURCE			\
	-D_LARGEFILE64_SOURCE                   \
	-D_FILE_OFFSET_BITS=64                  \
        -I$(top_srcdir)/lib			\
        -I$(top_srcdir)/lib/crypto_backend

