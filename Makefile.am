EXTRA_DIST = README.md SECURITY.md README.licensing CONTRIBUTING.md FAQ.md docs misc autogen.sh
EXTRA_DIST += meson_options.txt \
	meson.build \
	lib/crypto_backend/argon2/meson.build \
	lib/crypto_backend/meson.build \
	lib/meson.build \
	man/meson.build \
	po/meson.build \
	scripts/meson.build \
	src/meson.build \
	tests/meson.build \
	tests/fuzz/meson.build \
	tokens/meson.build \
	tokens/ssh/meson.build

SUBDIRS = po tests tests/fuzz
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
AM_CXXFLAGS = -Wall
AM_LDFLAGS =

if ENABLE_FUZZ_TARGETS
AM_CFLAGS += -fsanitize=fuzzer-no-link
AM_CXXFLAGS += -fsanitize=fuzzer-no-link
endif

LDADD = $(LTLIBINTL)

tmpfilesddir = @DEFAULT_TMPFILESDIR@

include_HEADERS =
lib_LTLIBRARIES =
noinst_LTLIBRARIES =
sbin_PROGRAMS =
man8_MANS =
tmpfilesd_DATA =
pkgconfig_DATA =
dist_noinst_DATA =

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
	--enable-internal-argon2 --enable-internal-sse-argon2 \
	--enable-external-tokens --enable-ssh-token --enable-asciidoc

distclean-local:
	-find . -name \*~ -o -name \*.orig -o -name \*.rej | xargs rm -f
	rm -rf autom4te.cache

clean-local:
	-rm -rf docs/doxygen_api_docs libargon2.la

install-data-local:
	$(MKDIR_P) -m 0755 $(DESTDIR)/${EXTERNAL_LUKS2_TOKENS_PATH}

uninstall-local:
	rmdir $(DESTDIR)/${EXTERNAL_LUKS2_TOKENS_PATH} 2>/dev/null || :

check-programs: libcryptsetup.la
	$(MAKE) -C tests $@

if ENABLE_FUZZ_TARGETS
fuzz-targets: libcryptsetup.la libcrypto_backend.la
	$(MAKE) -C tests/fuzz $@
endif
