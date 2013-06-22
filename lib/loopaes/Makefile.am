moduledir = $(libdir)/cryptsetup

noinst_LTLIBRARIES = libloopaes.la

libloopaes_la_CFLAGS = -Wall $(AM_CFLAGS) @CRYPTO_CFLAGS@

libloopaes_la_SOURCES = \
	loopaes.c \
	loopaes.h

AM_CPPFLAGS = -include config.h \
        -I$(top_srcdir)/lib			\
        -I$(top_srcdir)/lib/crypto_backend

