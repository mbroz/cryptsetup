#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with json area containing illegal bytes
# beyond well-formed json format.
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

QUOTE="[Homer J. Simpson]: Keep looking shocked and move slowly towards the cake."
SPACE=20

function prepare()
{
	cp $SRC_IMG $TGT_IMG
	test -d tmp || mkdir tmp
	read_luks2_json0 $TGT_IMG tmp/json0
	read_luks2_bin_hdr0 $TGT_IMG tmp/hdr0
	read_luks2_bin_hdr1 $TGT_IMG tmp/hdr1
}

function generate()
{
	json_str=$(< tmp/json0) # add illegal 'X' beyond json format
	json_len_orig=${#json_str}
	json_len=$((json_len_orig+${#QUOTE}+SPACE))
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	printf '%s' "$QUOTE" | _dd of=tmp/json0 seek=$((json_len_orig+SPACE)) bs=1 conv=notrunc

	merge_bin_hdr_with_json tmp/hdr0 tmp/json0 tmp/area0
	erase_checksum tmp/area0
	chks0=$(calc_sha256_checksum_file tmp/area0)
	write_checksum $chks0 tmp/area0
	write_luks2_hdr0 tmp/area0 $TGT_IMG
	kill_bin_hdr tmp/hdr1
	write_luks2_hdr1 tmp/hdr1 $TGT_IMG
}

function check()
{
	read_luks2_bin_hdr1 $TGT_IMG tmp/hdr_res1
	local str_res1=$(head -c 6 tmp/hdr_res1)
	test "$str_res1" = "VACUUM" || exit 2

	read_luks2_json0 $TGT_IMG tmp/json_res0
	chks_res0=$(read_sha256_checksum $TGT_IMG)
	test "$chks0" = "$chks_res0" || exit 2

	_dd if=tmp/json_res0 of=tmp/quote skip=$((json_len_orig+SPACE)) count=${#QUOTE} bs=1
	json_str_res0=$(head -c ${#QUOTE} tmp/quote)
	test "$json_str_res0" = "$QUOTE" || exit 2
}

function cleanup()
{
	rm -f tmp/*
}

test $# -eq 2 || exit 1

TGT_IMG=$1/$(test_img_name $0)
SRC_IMG=$2

prepare
generate
check
cleanup
