moduledir = $(libdir)/cryptsetup

noinst_LTLIBRARIES = libluks1.la

libluks1_la_CFLAGS = -Wall @LIBGCRYPT_CFLAGS@

libluks1_la_SOURCES = \
	af.c \
	pbkdf.c \
	keymanage.c \
	keyencryption.c \
	pbkdf.h \
	af.h \
	luks.h

INCLUDES = -D_GNU_SOURCE			\
	-D_LARGEFILE64_SOURCE                   \
	-D_FILE_OFFSET_BITS=64                  \
        -I$(top_srcdir)/lib

