TESTS = apitest

EXTRA_DIST = fileDiffer.py compatimage.img.bz2

apitest_SOURCES = apitest.c
apitest_LDADD = ../lib/libcryptsetup.la
apitest_LDFLAGS = -static
apitest_CFLAGS = -g -O0 -I$(top_srcdir)/lib/

check_PROGRAMS = apitest

compatimage.img:
	@bzip2 -k -d compatimage.img.bz2

# LUKS tests
ORIG_IMG = /tmp/luks-test-orig
IMG = /tmp/luks-test
IMG1 = /tmp/luks-test1


LUKS_HEADER = S0-5 S6-7 S8-39 S40-71 S72-103 S104-107 S108-111 R112-131 R132-163 S164-167 S168-207 A0-591

KEY_SLOT0 = S208-211 S212-215 R216-247 S248-251 S251-255
KEY_MATERIAL0 = R4096-68096
KEY_MATERIAL0_EXT = R4096-68096

KEY_SLOT1 = S256-259 S260-263 R264-295 S296-299 S300-303 
KEY_MATERIAL1 = R69632-133632
KEY_MATERIAL1_EXT = S69632-133632

LOOPDEV = /dev/loop5

test:
#	(cd ..; make clean; make CFLAGS=-Werror)
	@if [ `id -u` != 0 ]; then 	\
		echo Not root; \
	fi
	@if [ ! -e /tmp/key1 ]; then	\
		dd if=/dev/urandom of=/tmp/key1 count=1 bs=32; \
	fi
	@bzip2 -cd compatimage.img.bz2 > $(IMG)
	@-/sbin/losetup -d $(LOOPDEV)
	@/sbin/losetup $(LOOPDEV) $(IMG)

	@echo Case: open - compat image - acceptance check
# Image must not change
	@cp $(IMG) $(ORIG_IMG)
	echo "compatkey" | ../src/cryptsetup -v luksOpen $(LOOPDEV) dummy
	@sync
	./fileDiffer.py $(IMG) $(ORIG_IMG) 
	@-ls -l /dev/mapper/dummy > /dev/null
	@../src/cryptsetup remove dummy
	@echo "success"


	@echo Case: open - compat image - denial check
# Image must not change
	@cp $(IMG) $(ORIG_IMG)
	echo "wrongkey" | ../src/cryptsetup -v luksOpen $(LOOPDEV) dummy || true
	@sync
	./fileDiffer.py $(IMG) $(ORIG_IMG) 
	@echo "success"

	@echo Case: format
# All headers items and first key material section must change
	@cp $(IMG) $(ORIG_IMG)
	echo "key0" | ../src/cryptsetup -v -i 1000 -c aes-cbc-essiv:sha256 luksFormat $(LOOPDEV)
	@sync
	./fileDiffer.py $(IMG) $(ORIG_IMG) $(LUKS_HEADER) $(KEY_SLOT0) $(KEY_MATERIAL0)

	@echo Case: format using hash sha512
	@cp $(IMG) $(ORIG_IMG)
	echo "key0" | ../src/cryptsetup -v -i 1000 -h sha512 -c aes-cbc-essiv:sha256 luksFormat $(LOOPDEV)
	@sync
	./fileDiffer.py $(IMG) $(ORIG_IMG) $(LUKS_HEADER) $(KEY_SLOT0) $(KEY_MATERIAL0)

	@echo Case: open 
# Image must not change
	@cp $(IMG) $(ORIG_IMG)
	echo "key0" | ../src/cryptsetup -v luksOpen $(LOOPDEV) dummy
	@sync
	./fileDiffer.py $(IMG) $(ORIG_IMG) 
	@-ls -l /dev/mapper/dummy > /dev/null
	@../src/cryptsetup remove dummy
	@echo "success"

	@echo Case: add key
# Key Slot 1 and key material section 1 must change, the rest must not.
	@cp $(IMG) $(ORIG_IMG)
	echo -e "key0\nkey1" | ../src/cryptsetup -v luksAddKey $(LOOPDEV)
	@sync
	./fileDiffer.py $(IMG) $(ORIG_IMG) $(KEY_SLOT1) $(KEY_MATERIAL1)
	echo "key1" | ../src/cryptsetup -v luksOpen $(LOOPDEV) dummy
	@-ls -l /dev/mapper/dummy > /dev/null
	@../src/cryptsetup -v remove dummy
	@echo "success"

# Unsuccessful Key Delete - nothing may change
	@echo Case: unsuccessful delete
	@cp $(IMG) $(ORIG_IMG)
	echo "invalid" | ../src/cryptsetup -v luksDelKey $(LOOPDEV) 1 || true
	@sync
	./fileDiffer.py $(IMG) $(ORIG_IMG)
	@echo "success"

# Delete Key Test
# Key Slot 1 and key material section 1 must change, the rest must not
	@echo Case: successful delete
	@cp $(IMG) $(ORIG_IMG)
	../src/cryptsetup -v -q luksDelKey $(LOOPDEV) 1
	@sync
	./fileDiffer.py $(IMG) $(ORIG_IMG) $(KEY_SLOT1) $(KEY_MATERIAL1_EXT)
	echo "key1" | ../src/cryptsetup -v luksOpen $(LOOPDEV) dummy 2>/dev/null || true
	echo "key0" | ../src/cryptsetup -v luksOpen $(LOOPDEV) dummy 2>/dev/null 
	@../src/cryptsetup -v remove dummy
	@echo "success"

# Non-Exclusive Open test
#	@echo Case: Non-Exclusive Open
#	echo "key0" | ../src/cryptsetup -v --readonly luksOpen $(LOOPDEV) dummy1 2>/dev/null
# must fail
#	echo "key0" | ../src/cryptsetup -v --readonly luksOpen $(LOOPDEV) dummy2 2>/dev/null || true 
#	echo "key0" | ../src/cryptsetup -v --non-exclusive --readonly luksOpen $(LOOPDEV) dummy2 2>/dev/null
#	@../src/cryptsetup -v remove dummy1
#	@../src/cryptsetup -v remove dummy2


# Key Slot 1 and key material section 1 must change, the rest must not
	@echo Case: add key test for key files
	@cp $(IMG) $(ORIG_IMG)
	echo "key0" | ../src/cryptsetup -v luksAddKey $(LOOPDEV) /tmp/key1
	@sync
	./fileDiffer.py $(IMG) $(ORIG_IMG) $(KEY_SLOT1) $(KEY_MATERIAL1)
	../src/cryptsetup -d /tmp/key1 -v luksOpen $(LOOPDEV) dummy
	@-ls -l /dev/mapper/dummy > /dev/null
	@../src/cryptsetup -v remove dummy
	@echo "success"

	@echo Case: delete key test with /tmp/key1 as remaining key
# Key Slot 1 and key material section 1 must change, the rest must not
	@cp $(IMG) $(ORIG_IMG)
	../src/cryptsetup -v -d /tmp/key1 luksDelKey $(LOOPDEV) 0
	@sync
	./fileDiffer.py $(IMG) $(ORIG_IMG) $(KEY_SLOT0) $(KEY_MATERIAL0_EXT)
	echo "key0" | ../src/cryptsetup -v luksOpen $(LOOPDEV) dummy 2>/dev/null || true
	../src/cryptsetup -v luksOpen -d /tmp/key1 $(LOOPDEV) dummy 2>/dev/null
	@../src/cryptsetup -v remove dummy
	@echo "success"

# Delete last slot
	@echo Case: delete last key
	@cp $(IMG) $(ORIG_IMG)
	@echo "key0" | ../src/cryptsetup -v luksFormat $(LOOPDEV)
	echo "key0" | ../src/cryptsetup -v luksKillSlot $(LOOPDEV) 0
	@sync
	echo "key0" | ../src/cryptsetup -v luksOpen $(LOOPDEV) dummy 2>/dev/null || true
	@echo "success"

# Format test for ESSIV, and some other parameters.
	@echo Case: parameter variation test
	@dd if=/dev/zero of=$(IMG) count=20000
	@cp $(IMG) $(ORIG_IMG)
	@../src/cryptsetup -q -v -i 1000 -c aes-cbc-essiv:sha256 luksFormat $(LOOPDEV) /tmp/key1
	@sync
	./fileDiffer.py $(IMG) $(ORIG_IMG) $(LUKS_HEADER) $(KEY_SLOT0) $(KEY_MATERIAL0)
	@../src/cryptsetup -d /tmp/key1 -v luksOpen $(LOOPDEV) dummy
	@-ls -l /dev/mapper/dummy > /dev/null && echo "success"
	@../src/cryptsetup -v remove dummy

	@-/sbin/losetup -d $(LOOPDEV)
