moduledir = $(libdir)/cryptsetup

noinst_LTLIBRARIES = libverity.la

libverity_la_CFLAGS = -Wall $(AM_CFLAGS) @CRYPTO_CFLAGS@

libverity_la_SOURCES = \
	verity_hash.c \
	verity.c \
	verity.h \
	fec.c \
	fec.h \
	libfec/encode_rs_char.c \
	libfec/encode_rs.h \
	libfec/init_rs_char.c \
	libfec/init_rs.h \
	libfec/rs-common.h \
	libfec/char.h \
	libfec/fec.h

AM_CPPFLAGS = -include config.h \
        -I$(top_srcdir)/lib			\
        -I$(top_srcdir)/lib/crypto_backend
