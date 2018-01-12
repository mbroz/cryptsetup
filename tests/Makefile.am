TESTS = api-test \
	api-test-2 \
	compat-test \
	compat-test2 \
	loopaes-test \
	align-test \
	discards-test \
	mode-test \
	password-hash-test \
	tcrypt-compat-test \
	luks1-compat-test \
	device-test \
	keyring-test \
	keyring-compat-test \
	luks2-validation-test \
	luks2-integrity-test

if VERITYSETUP
TESTS += verity-compat-test
endif

if REENCRYPT
TESTS += reencryption-compat-test reencryption-compat-test2

endif

if INTEGRITYSETUP
TESTS += integrity-compat-test
endif

EXTRA_DIST = compatimage.img.bz2 compatv10image.img.bz2 \
	compatimage2.img.xz \
	conversion_imgs.tar.xz \
	luks2_keyslot_unassigned.img.xz \
	img_fs_ext4.img.bz2 img_fs_vfat.img.bz2 img_fs_xfs.img.bz2 \
	valid_header_file.bz2 \
	luks2_valid_hdr.img.xz \
	luks2_header_requirements.xz \
	luks2_header_requirements_free.xz \
	evil_hdr-payload_overwrite.bz2 \
	evil_hdr-stripes_payload_dmg.bz2 \
	evil_hdr-luks_hdr_damage.bz2 \
	evil_hdr-small_luks_device.bz2 \
	evil_hdr-keyslot_overlap.bz2 \
	tcrypt-images.tar.bz2 \
	luks1-images.tar.bz2 \
	compat-test \
	compat-test2 \
	loopaes-test align-test discards-test mode-test password-hash-test \
	verity-compat-test \
	reencryption-compat-test \
	reencryption-compat-test2 \
	tcrypt-compat-test \
	luks1-compat-test \
	luks2-validation-test generators \
	luks2-integrity-test \
	device-test \
	keyring-test \
	keyring-compat-test \
	integrity-compat-test \
	cryptsetup-valg-supps valg.sh valg-api.sh

CLEANFILES = cryptsetup-tst* valglog*
clean-local:
	-rm -rf tcrypt-images luks1-images luks2-images conversion_imgs luks2_valid_hdr.img

differ_SOURCES = differ.c
differ_CFLAGS = $(AM_CFLAGS) -Wall -O2

api_test_SOURCES = api-test.c api_test.h test_utils.c
api_test_LDADD = ../libcryptsetup.la
api_test_LDFLAGS = $(AM_LDFLAGS) -static
api_test_CFLAGS = -g -Wall -O0 $(AM_CFLAGS) -I$(top_srcdir)/lib/ -I$(top_srcdir)/lib/luks1
api_test_CPPFLAGS = $(AM_CPPFLAGS) -include config.h

api_test_2_SOURCES = api-test-2.c api_test.h test_utils.c
api_test_2_LDADD = ../libcryptsetup.la
api_test_2_LDFLAGS = $(AM_LDFLAGS) -static
api_test_2_CFLAGS = -g -Wall -O0 $(AM_CFLAGS) -I$(top_srcdir)/lib/ -I$(top_srcdir)/lib/luks1
api_test_2_CPPFLAGS = $(AM_CPPFLAGS) -include config.h

check_PROGRAMS = api-test api-test-2 differ

conversion_imgs:
	@tar xJf conversion_imgs.tar.xz

compatimage.img:
	@bzip2 -k -d compatimage.img.bz2

valgrind-check: api-test api-test-2 differ
	@VALG=1 ./compat-test
	@VALG=1 ./compat-test2
	@VALG=1 ./luks2-validation-test
	@VALG=1 ./verity-compat-test
	@VALG=1 ./integrity-compat-test
	@INFOSTRING="api-test-000" ./valg-api.sh ./api-test
	@INFOSTRING="api-test-002" ./valg-api.sh ./api-test-2

.PHONY: valgrind-check
