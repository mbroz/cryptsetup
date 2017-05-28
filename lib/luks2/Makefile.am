moduledir = $(libdir)/cryptsetup

noinst_LTLIBRARIES = libluks2.la

libluks2_la_CFLAGS = -Wall $(AM_CFLAGS) @CRYPTO_CFLAGS@

libluks2_la_SOURCES = \
	base64.c \
	base64.h \
	luks2_disk_metadata.c \
	luks2_json_format.c \
	luks2_json_metadata.c \
	luks2_luks1_convert.c \
	luks2_digest.c \
	luks2_digest_pbkdf2.c \
	luks2_keyslot.c \
	luks2_keyslot_luks2.c \
	luks2_token_keyring.c \
	luks2_token.c \
	luks2_internal.h \
	luks2.h

AM_CPPFLAGS = -include config.h \
        -I$(top_srcdir)/lib			\
        -I$(top_srcdir)/lib/crypto_backend
