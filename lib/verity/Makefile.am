moduledir = $(libdir)/cryptsetup

noinst_LTLIBRARIES = libverity.la

libverity_la_CFLAGS = -Wall @CRYPTO_CFLAGS@

libverity_la_SOURCES = \
	verity_hash.c \
	verity.c \
	verity.h

INCLUDES = -D_GNU_SOURCE			\
	-D_LARGEFILE64_SOURCE                   \
	-D_FILE_OFFSET_BITS=64                  \
        -I$(top_srcdir)/lib			\
        -I$(top_srcdir)/lib/crypto_backend
