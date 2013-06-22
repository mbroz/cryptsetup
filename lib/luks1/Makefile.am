moduledir = $(libdir)/cryptsetup

noinst_LTLIBRARIES = libluks1.la

libluks1_la_CFLAGS = -Wall $(AM_CFLAGS) @CRYPTO_CFLAGS@

libluks1_la_SOURCES = \
	af.c \
	keymanage.c \
	keyencryption.c \
	af.h \
	luks.h

AM_CPPFLAGS = -include config.h \
        -I$(top_srcdir)/lib			\
        -I$(top_srcdir)/lib/crypto_backend

