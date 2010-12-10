TESTS = api-test compat-test align-test mode-test password-hash-test

EXTRA_DIST = compatimage.img.bz2 align-test compat-test mode-test password-hash-test

differ_SOURCES = differ.c
differ_CFLAGS = -Wall -O2

api_test_SOURCES = api-test.c
api_test_LDADD = ../lib/libcryptsetup.la
api_test_LDFLAGS = -static
api_test_CFLAGS = -g -Wall -O0 -I$(top_srcdir)/lib/

check_PROGRAMS = api-test differ

compatimage.img:
	@bzip2 -k -d compatimage.img.bz2
