moduledir = $(libdir)/cryptsetup

noinst_LTLIBRARIES = libloopaes.la

libloopaes_la_CFLAGS = -Wall @CRYPTO_CFLAGS@

libloopaes_la_SOURCES = \
	loopaes.c \
	loopaes.h

INCLUDES = -D_GNU_SOURCE			\
	-D_LARGEFILE64_SOURCE                   \
	-D_FILE_OFFSET_BITS=64                  \
        -I$(top_srcdir)/lib			\
        -I$(top_srcdir)/lib/crypto_backend

