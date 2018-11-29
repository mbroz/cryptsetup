#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary with predefined json_size where keyslots size
# overflows in data area (segment offset)
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
	# 64KiB metadata
	TEST_MDA_SIZE=$LUKS2_HDR_SIZE_64K

	TEST_MDA_SIZE_BYTES=$((TEST_MDA_SIZE*512))
	TEST_JSN_SIZE=$((TEST_MDA_SIZE-LUKS2_BIN_HDR_SIZE))
	KEYSLOTS_OFFSET=$((TEST_MDA_SIZE*1024))
	JSON_DIFF=$(((TEST_MDA_SIZE-LUKS2_HDR_SIZE)*1024))
	JSON_SIZE=$((TEST_JSN_SIZE*512))
	DATA_OFFSET=16777216

	json_str=$(jq -c --arg jdiff $JSON_DIFF --arg jsize $JSON_SIZE --arg off $DATA_OFFSET \
			 --arg mda $((2*TEST_MDA_SIZE_BYTES)) \
		   '.keyslots[].area.offset |= ( . | tonumber + ($jdiff | tonumber) | tostring) |
		    .config.json_size = $jsize |
		    .config.keyslots_size = (((($off | tonumber) - ($mda | tonumber) + 4096)) | tostring ) |
		    .segments."0".offset = $off' $TMPDIR/json0)
	test -n "$json_str" || exit 2
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	write_luks2_json "$json_str" $TMPDIR/json0 $TEST_JSN_SIZE

	write_bin_hdr_size $TMPDIR/hdr0 $TEST_MDA_SIZE_BYTES
	write_bin_hdr_size $TMPDIR/hdr1 $TEST_MDA_SIZE_BYTES

	merge_bin_hdr_with_json $TMPDIR/hdr0 $TMPDIR/json0 $TMPDIR/area0 $TEST_JSN_SIZE
	merge_bin_hdr_with_json $TMPDIR/hdr1 $TMPDIR/json0 $TMPDIR/area1 $TEST_JSN_SIZE

	erase_checksum $TMPDIR/area0
	chks0=$(calc_sha256_checksum_file $TMPDIR/area0)
	write_checksum $chks0 $TMPDIR/area0

	erase_checksum $TMPDIR/area1
	chks0=$(calc_sha256_checksum_file $TMPDIR/area1)
	write_checksum $chks0 $TMPDIR/area1

	kill_bin_hdr $TMPDIR/area1

	write_luks2_hdr0 $TMPDIR/area0 $TGT_IMG $TEST_MDA_SIZE
	write_luks2_hdr1 $TMPDIR/area1 $TGT_IMG $TEST_MDA_SIZE
}

function check()
{
	read_luks2_bin_hdr1 $TGT_IMG $TMPDIR/hdr_res1 $TEST_MDA_SIZE
	local str_res1=$(head -c 6 $TMPDIR/hdr_res1)
	test "$str_res1" = "VACUUM" || exit 2
	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0 $TEST_JSN_SIZE
	jq -c --arg koff $KEYSLOTS_OFFSET --arg jsize $JSON_SIZE --arg off $DATA_OFFSET --arg mda $((2*TEST_MDA_SIZE_BYTES)) \
		'if ([.keyslots[].area.offset] | map(tonumber) | min | tostring != $koff) or
		    (.config.json_size != $jsize) or
		    (.config.keyslots_size != (((($off | tonumber) - ($mda | tonumber) + 4096)) | tostring ))
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
