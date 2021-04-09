TESTS = 00modules-test \
	api-test \
	api-test-2 \
	compat-test-args \
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
	bitlk-compat-test \
	run-all-symbols

if VERITYSETUP
TESTS += verity-compat-test
endif

if REENCRYPT
TESTS += reencryption-compat-test reencryption-compat-test2 luks2-reencryption-test
endif

if INTEGRITYSETUP
TESTS += integrity-compat-test
endif

if SSHPLUGIN_TOKEN
TESTS += ssh-plugin-test
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
	compat-test-args \
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
	bitlk-images.tar.xz \
	ssh-plugin-test \
	generate-symbols-list \
	run-all-symbols

CLEANFILES = cryptsetup-tst* valglog* *-fail-*.log test-symbols-list.h
clean-local:
	-rm -rf tcrypt-images luks1-images luks2-images bitlk-images conversion_imgs luks2_valid_hdr.img blkid-luks2-pv-img blkid-luks2-pv-img.bcp

LDADD = $(LTLIBINTL)

differ_SOURCES = differ.c
differ_CFLAGS = $(AM_CFLAGS) -Wall -O2

api_test_SOURCES = api-test.c api_test.h test_utils.c
api_test_LDADD = $(LDADD) ../libcryptsetup.la
api_test_LDFLAGS = $(AM_LDFLAGS) -static
api_test_CFLAGS = -g -Wall -O0 $(AM_CFLAGS) -I$(top_srcdir)/lib
api_test_CPPFLAGS = $(AM_CPPFLAGS) -include config.h

api_test_2_SOURCES = api-test-2.c api_test.h test_utils.c
api_test_2_LDADD = $(LDADD) ../libcryptsetup.la
api_test_2_LDFLAGS = $(AM_LDFLAGS) -static
api_test_2_CFLAGS = -g -Wall -O0 $(AM_CFLAGS) -I$(top_srcdir)/lib
api_test_2_CPPFLAGS = $(AM_CPPFLAGS) -include config.h

vectors_test_SOURCES = crypto-vectors.c
vectors_test_LDADD = ../libcrypto_backend.la @CRYPTO_LIBS@ @LIBARGON2_LIBS@
vectors_test_LDFLAGS = $(AM_LDFLAGS) -static
vectors_test_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/lib @CRYPTO_CFLAGS@
vectors_test_CPPFLAGS = $(AM_CPPFLAGS) -include config.h

unit_utils_io_SOURCES = unit-utils-io.c
unit_utils_io_LDADD = ../libutils_io.la
unit_utils_io_LDFLAGS = $(AM_LDFLAGS) -static
unit_utils_io_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/lib
unit_utils_io_CPPFLAGS = $(AM_CPPFLAGS) -include config.h

BUILT_SOURCES = test-symbols-list.h

test-symbols-list.h: $(top_srcdir)/lib/libcryptsetup.sym generate-symbols-list
	$(srcdir)/generate-symbols-list $(top_srcdir)/lib/libcryptsetup.sym > $(builddir)/test-symbols-list.h

all_symbols_test_SOURCES = all-symbols-test.c
nodist_all_symbols_test_SOURCES = test-symbols-list.h
all_symbols_test.$(OBJEXT): test-symbols-list.h
all_symbols_test_CFLAGS = -ldl
all_symbols_test_CPPFLAGS = $(AM_CPPFLAGS) -D_GNU_SOURCE

check_PROGRAMS = api-test api-test-2 differ vectors-test unit-utils-io all-symbols-test

conversion_imgs:
	@tar xJf conversion_imgs.tar.xz

compatimage.img:
	@xz -k -d compatimage.img.xz

valgrind-check: api-test api-test-2 differ
	@VALG=1 ./compat-test-args
	@VALG=1 ./compat-test
	@VALG=1 ./compat-test2
	@VALG=1 ./luks2-validation-test
	@VALG=1 ./verity-compat-test
	@VALG=1 ./integrity-compat-test
	@INFOSTRING="api-test-000" ./valg-api.sh ./api-test
	@INFOSTRING="api-test-002" ./valg-api.sh ./api-test-2
	@VALG=1 ./luks2-reencryption-test
	@VALG=1 ./bitlk-compat-test
	@grep -l "ERROR SUMMARY: [^0] errors" valglog* || echo "No leaks detected."

.PHONY: valgrind-check
