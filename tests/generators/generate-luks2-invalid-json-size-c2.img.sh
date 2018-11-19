#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with config json size mismatching
# value in binary header
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

function prepare()
{
	cp $SRC_IMG $TGT_IMG
	test -d $TMPDIR || mkdir $TMPDIR
	read_luks2_json0 $TGT_IMG $TMPDIR/json0
	read_luks2_bin_hdr0 $TGT_IMG $TMPDIR/hdr0
	read_luks2_bin_hdr1 $TGT_IMG $TMPDIR/hdr1
}

function generate()
{
	JS=$(((LUKS2_HDR_SIZE-LUKS2_BIN_HDR_SIZE)*512))
	TEST_MDA_SIZE=$LUKS2_HDR_SIZE_32K
	TEST_MDA_SIZE_BYTES=$((TEST_MDA_SIZE*512))
	TEST_JSN_SIZE=$((TEST_MDA_SIZE-LUKS2_BIN_HDR_SIZE))

	json_str=$(jq -c '.' $TMPDIR/json0)

	write_luks2_json "$json_str" $TMPDIR/json0 $TEST_JSN_SIZE

	write_bin_hdr_size $TMPDIR/hdr0 $TEST_MDA_SIZE_BYTES
	write_bin_hdr_size $TMPDIR/hdr1 $TEST_MDA_SIZE_BYTES
	write_bin_hdr_offset $TMPDIR/hdr1 $TEST_MDA_SIZE_BYTES

	merge_bin_hdr_with_json $TMPDIR/hdr0 $TMPDIR/json0 $TMPDIR/area0 $TEST_JSN_SIZE
	merge_bin_hdr_with_json $TMPDIR/hdr1 $TMPDIR/json0 $TMPDIR/area1 $TEST_JSN_SIZE

	erase_checksum $TMPDIR/area0
	chks0=$(calc_sha256_checksum_file $TMPDIR/area0)
	write_checksum $chks0 $TMPDIR/area0

	erase_checksum $TMPDIR/area1
	chks0=$(calc_sha256_checksum_file $TMPDIR/area1)
	write_checksum $chks0 $TMPDIR/area1

	write_luks2_hdr0 $TMPDIR/area0 $TGT_IMG $TEST_MDA_SIZE
	write_luks2_hdr1 $TMPDIR/area1 $TGT_IMG $TEST_MDA_SIZE
}

function check()
{
	read_luks2_bin_hdr0 $TGT_IMG $TMPDIR/hdr_res0
	local str_res1=$(head -c 4 $TMPDIR/hdr_res0)
	test "$str_res1" = "LUKS" || exit 2

	read_luks2_bin_hdr1 $TGT_IMG $TMPDIR/hdr_res1 $TEST_MDA_SIZE
	local str_res1=$(head -c 4 $TMPDIR/hdr_res1)
	test "$str_res1" = "SKUL" || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	jq -c --arg js $JS 'if .config.json_size != ( $js | tostring )
	       then error("Unexpected value in result json") else empty end' $TMPDIR/json_res0 || exit 5
}

function cleanup()
{
	rm -f $TMPDIR/*
	rm -fd $TMPDIR
}

test $# -eq 2 || exit 1

TGT_IMG=$1/$(test_img_name $0)
SRC_IMG=$2

prepare
generate
check
cleanup
