moduledir = $(libdir)/cryptsetup

noinst_LTLIBRARIES = libverity.la

libverity_la_CFLAGS = -Wall $(AM_CFLAGS) @CRYPTO_CFLAGS@

libverity_la_SOURCES = \
	verity_hash.c \
	verity_fec.c \
	verity.c \
	verity.h \
	rs_encode_char.c \
	rs.h

AM_CPPFLAGS = -include config.h \
        -I$(top_srcdir)/lib			\
        -I$(top_srcdir)/lib/crypto_backend
