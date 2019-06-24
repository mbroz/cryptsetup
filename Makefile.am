EXTRA_DIST = COPYING.LGPL FAQ docs misc
SUBDIRS = po tests
CLEANFILES =
DISTCLEAN_TARGETS =

AM_CPPFLAGS = \
	-include config.h \
	-I$(top_srcdir)/lib \
        -DDATADIR=\""$(datadir)"\"              \
        -DLOCALEDIR=\""$(datadir)/locale"\"     \
        -DLIBDIR=\""$(libdir)"\"                \
        -DPREFIX=\""$(prefix)"\"                \
        -DSYSCONFDIR=\""$(sysconfdir)"\"        \
        -DVERSION=\""$(VERSION)"\"
AM_CFLAGS = -Wall
AM_LDFLAGS =

LDADD = $(LTLIBINTL) -lm

tmpfilesddir = @DEFAULT_TMPFILESDIR@

noinst_LTLIBRARIES =
sbin_PROGRAMS =
man8_MANS =
tmpfilesd_DATA =

include man/Makemodule.am

include scripts/Makemodule.am

if CRYPTO_INTERNAL_ARGON2
include lib/crypto_backend/argon2/Makemodule.am
endif
include lib/crypto_backend/Makemodule.am
include lib/Makemodule.am

include src/Makemodule.am
include tokens/Makemodule.am

ACLOCAL_AMFLAGS = -I m4

DISTCHECK_CONFIGURE_FLAGS = 	\
	--with-tmpfilesdir=$$dc_install_base/usr/lib/tmpfiles.d \
	--enable-internal-argon2 --enable-internal-sse-argon2

distclean-local:
	-find . -name \*~ -o -name \*.orig -o -name \*.rej | xargs rm -f
	rm -rf autom4te.cache

clean-local:
	-rm -rf docs/doxygen_api_docs libargon2.la
