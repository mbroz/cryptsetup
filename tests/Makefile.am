TESTS = 00modules-test \
	api-test \
	api-test-2 \
	compat-test \
	compat-test2 \
	loopaes-test \
	align-test \
	align-test2 \
	discards-test \
	mode-test \
	password-hash-test \
	tcrypt-compat-test \
	luks1-compat-test \
	device-test \
	keyring-test \
	keyring-compat-test \
	luks2-validation-test \
	luks2-integrity-test \
	vectors-test \
	blockwise-compat \
	bitlk-compat-test

if VERITYSETUP
TESTS += verity-compat-test
endif

if REENCRYPT
TESTS += reencryption-compat-test reencryption-compat-test2 luks2-reencryption-test
endif

if INTEGRITYSETUP
TESTS += integrity-compat-test
endif

EXTRA_DIST = compatimage.img.xz compatv10image.img.xz \
	compatimage2.img.xz \
	conversion_imgs.tar.xz \
	luks2_keyslot_unassigned.img.xz \
	img_fs_ext4.img.xz img_fs_vfat.img.xz img_fs_xfs.img.xz \
	valid_header_file.xz \
	luks2_valid_hdr.img.xz \
	luks2_header_requirements.xz \
	luks2_header_requirements_free.xz \
	luks2_mda_images.tar.xz \
	evil_hdr-payload_overwrite.xz \
	evil_hdr-stripes_payload_dmg.xz \
	evil_hdr-luks_hdr_damage.xz \
	evil_hdr-small_luks_device.xz \
	evil_hdr-keyslot_overlap.xz \
	tcrypt-images.tar.xz \
	luks1-images.tar.xz \
	00modules-test \
	compat-test \
	compat-test2 \
	loopaes-test align-test discards-test mode-test password-hash-test \
	align-test2 verity-compat-test \
	reencryption-compat-test \
	reencryption-compat-test2 \
	luks2-reencryption-test \
	tcrypt-compat-test \
	luks1-compat-test \
	luks2-validation-test generators \
	luks2-integrity-test \
	device-test \
	keyring-test \
	keyring-compat-test \
	integrity-compat-test \
	cryptsetup-valg-supps valg.sh valg-api.sh \
	blockwise-compat \
	blkid-luks2-pv.img.xz \
	Makefile.localtest \
	bitlk-compat-test \
	bitlk-images.tar.xz

CLEANFILES = cryptsetup-tst* valglog* *-fail-*.log
clean-local:
	-rm -rf tcrypt-images luks1-images luks2-images bitlk-images conversion_imgs luks2_valid_hdr.img blkid-luks2-pv-img blkid-luks2-pv-img.bcp

differ_SOURCES = differ.c
differ_CFLAGS = $(AM_CFLAGS) -Wall -O2

api_test_SOURCES = api-test.c api_test.h test_utils.c
api_test_LDADD = $(LDADD) ../libcryptsetup.la
api_test_LDFLAGS = $(AM_LDFLAGS) -static
api_test_CFLAGS = -g -Wall -O0 $(AM_CFLAGS) -I$(top_srcdir)/lib/ -I$(top_srcdir)/lib/luks1
api_test_CPPFLAGS = $(AM_CPPFLAGS) -include config.h

api_test_2_SOURCES = api-test-2.c api_test.h test_utils.c
api_test_2_LDADD = $(LDADD) ../libcryptsetup.la
api_test_2_LDFLAGS = $(AM_LDFLAGS) -static
api_test_2_CFLAGS = -g -Wall -O0 $(AM_CFLAGS) -I$(top_srcdir)/lib/ -I$(top_srcdir)/lib/luks1
api_test_2_CPPFLAGS = $(AM_CPPFLAGS) -include config.h

vectors_test_SOURCES = crypto-vectors.c
vectors_test_LDADD = ../libcrypto_backend.la @CRYPTO_LIBS@ @LIBARGON2_LIBS@
vectors_test_LDFLAGS = $(AM_LDFLAGS) -static
vectors_test_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/lib/crypto_backend/ @CRYPTO_CFLAGS@
vectors_test_CPPFLAGS = $(AM_CPPFLAGS) -include config.h

unit_utils_io_SOURCES = unit-utils-io.c
unit_utils_io_LDADD = ../libutils_io.la
unit_utils_io_LDFLAGS = $(AM_LDFLAGS) -static
unit_utils_io_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/lib
unit_utils_io_CPPFLAGS = $(AM_CPPFLAGS) -include config.h

check_PROGRAMS = api-test api-test-2 differ vectors-test unit-utils-io

conversion_imgs:
	@tar xJf conversion_imgs.tar.xz

compatimage.img:
	@xz -k -d compatimage.img.xz

valgrind-check: api-test api-test-2 differ
	@VALG=1 ./compat-test2
	@VALG=1 ./luks2-validation-test
	@VALG=1 ./verity-compat-test
	@VALG=1 ./integrity-compat-test
	@INFOSTRING="api-test-000" ./valg-api.sh ./api-test
	@INFOSTRING="api-test-002" ./valg-api.sh ./api-test-2
	@VALG=1 ./luks2-reencryption-test
	@VALG=1 ./compat-test

.PHONY: valgrind-check
