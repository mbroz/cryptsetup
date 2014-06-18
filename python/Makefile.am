AM_CPPFLAGS = -include $(top_srcdir)/config.h -I$(top_srcdir)/lib $(PYTHON_INCLUDES)
EXTRA_DIST = pycryptsetup-test.py
CLEANFILES = *.img

if PYTHON_CRYPTSETUP
TESTS = pycryptsetup-test.py

pyexec_LTLIBRARIES = pycryptsetup.la

pycryptsetup_la_SOURCES = pycryptsetup.c
pycryptsetup_la_CPPFLAGS = $(AM_CPPFLAGS) $(PYTHON_CPPFLAGS) -fno-strict-aliasing
pycryptsetup_la_LDFLAGS = -avoid-version -module -shared -export-dynamic
pycryptsetup_la_LIBADD = $(top_builddir)/lib/libcryptsetup.la $(PYTHON_LIBS)
else
all:
endif
