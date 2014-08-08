TESTS = api-test \
	compat-test \
	loopaes-test \
	align-test \
	discards-test \
	mode-test \
	password-hash-test \
	tcrypt-compat-test \
	luks1-compat-test \
	device-test

if VERITYSETUP
TESTS += verity-compat-test
endif

if REENCRYPT
TESTS += reencryption-compat-test
endif

EXTRA_DIST = compatimage.img.bz2 compatv10image.img.bz2 \
	img_fs_ext4.img.bz2 img_fs_xfs.img.bz2 \
	valid_header_file.bz2 \
	evil_hdr-payload_overwrite.bz2 \
	evil_hdr-stripes_payload_dmg.bz2 \
	evil_hdr-luks_hdr_damage.bz2 \
	evil_hdr-small_luks_device.bz2 \
	tcrypt-images.tar.bz2 \
	luks1-images.tar.bz2 \
	compat-test loopaes-test align-test discards-test mode-test password-hash-test \
	verity-compat-test \
	reencryption-compat-test \
	tcrypt-compat-test \
	luks1-compat-test \
	device-test \
	cryptsetup-valg-supps valg.sh valg-api.sh

CLEANFILES = cryptsetup-tst* valglog*
clean-local:
	-rm -rf tcrypt-images luks1-images

differ_SOURCES = differ.c
differ_CFLAGS = $(AM_CFLAGS) -Wall -O2

api_test_SOURCES = api-test.c $(top_srcdir)/lib/utils_loop.c
api_test_LDADD = ../lib/libcryptsetup.la
api_test_LDFLAGS = $(AM_LDFLAGS) -static
api_test_CFLAGS = -g -Wall -O0 $(AM_CFLAGS) -I$(top_srcdir)/lib/ -I$(top_srcdir)/lib/luks1
api_test_CPPFLAGS = $(AM_CPPFLAGS) -include config.h

check_PROGRAMS = api-test differ

compatimage.img:
	@bzip2 -k -d compatimage.img.bz2

valgrind-check: api-test differ
	@VALG=1 ./compat-test
	@INFOSTRING="api-test-000" ./valg-api.sh ./api-test

.PHONY: valgrind-check
