INCLUDES = \
	-I$(top_srcdir)				\
	-I$(top_srcdir)/lib			\
	-DDATADIR=\""$(datadir)"\"		\
	-DLOCALEDIR=\""$(datadir)/locale"\"	\
	-DLIBDIR=\""$(libdir)"\"		\
	-DPREFIX=\""$(prefix)"\"		\
	-DSYSCONFDIR=\""$(sysconfdir)"\"	\
	-DVERSION=\""$(VERSION)"\"		\
	-D_GNU_SOURCE

cryptsetup_SOURCES = \
	cryptsetup.c				\
	cryptsetup.h

cryptsetup_LDADD = \
	@POPT_LIBS@				\
	$(top_srcdir)/lib/libcryptsetup.la

if STATIC_CRYPTSETUP
_STATIC_FLAGS = -all-static
endif

cryptsetup_LDFLAGS = \
	$(_STATIC_FLAGS) 

sbin_PROGRAMS=cryptsetup
