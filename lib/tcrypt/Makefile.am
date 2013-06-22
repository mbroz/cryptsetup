moduledir = $(libdir)/cryptsetup

noinst_LTLIBRARIES = libtcrypt.la

libtcrypt_la_CFLAGS = -Wall $(AM_CFLAGS) @CRYPTO_CFLAGS@

libtcrypt_la_SOURCES = \
	tcrypt.c \
	tcrypt.h

AM_CPPFLAGS = -include config.h \
        -I$(top_srcdir)/lib			\
        -I$(top_srcdir)/lib/crypto_backend

