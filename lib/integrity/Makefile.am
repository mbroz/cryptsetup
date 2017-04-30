moduledir = $(libdir)/cryptsetup

noinst_LTLIBRARIES = libintegrity.la

libintegrity_la_CFLAGS = -Wall $(AM_CFLAGS) @CRYPTO_CFLAGS@

libintegrity_la_SOURCES = \
	integrity.c \
	integrity.h

AM_CPPFLAGS = -include config.h \
        -I$(top_srcdir)/lib			\
        -I$(top_srcdir)/lib/crypto_backend
