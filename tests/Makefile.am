TESTS = apitest compat-test

EXTRA_DIST = fileDiffer.py compatimage.img.bz2 align_test compat-test

apitest_SOURCES = apitest.c
apitest_LDADD = ../lib/libcryptsetup.la
apitest_LDFLAGS = -static
apitest_CFLAGS = -g -Wall -O0 -I$(top_srcdir)/lib/

check_PROGRAMS = apitest

compatimage.img:
	@bzip2 -k -d compatimage.img.bz2
