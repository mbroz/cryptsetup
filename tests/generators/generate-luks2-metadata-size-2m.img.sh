#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary with predefined json_size. There's only limited
# set of values allowed as json size in config section of LUKS2
# metadata
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

generate()
{
	# 2 MiB metadata
	TEST_MDA_SIZE=$LUKS2_HDR_SIZE_2M

	TEST_MDA_SIZE_BYTES=$((TEST_MDA_SIZE*512))
	TEST_JSN_SIZE=$((TEST_MDA_SIZE-LUKS2_BIN_HDR_SIZE))
	KEYSLOTS_OFFSET=$((TEST_MDA_SIZE*1024))
	JSON_DIFF=$(((TEST_MDA_SIZE-LUKS2_HDR_SIZE)*1024))
	JSON_SIZE=$((TEST_JSN_SIZE*512))
	DATA_OFFSET=16777216

	json_str=$(jq -c --arg jdiff $JSON_DIFF --arg jsize $JSON_SIZE --arg off $DATA_OFFSET \
		   '.keyslots[].area.offset |= ( . | tonumber + ($jdiff | tonumber) | tostring) |
		    .config.json_size = $jsize |
		    .segments."0".offset = $off' $TMPDIR/json0)
	test -n "$json_str" || exit 2
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	write_luks2_json "$json_str" $TMPDIR/json0 $TEST_JSN_SIZE
	write_luks2_json "$json_str" $TMPDIR/json1 $TEST_JSN_SIZE

	write_bin_hdr_size $TMPDIR/hdr0 $TEST_MDA_SIZE_BYTES
	write_bin_hdr_size $TMPDIR/hdr1 $TEST_MDA_SIZE_BYTES

	lib_mangle_json_hdr0 $TEST_MDA_SIZE $TEST_JSN_SIZE
	lib_mangle_json_hdr1 $TEST_MDA_SIZE $TEST_JSN_SIZE kill
}

check()
{
	lib_hdr1_killed $TEST_MDA_SIZE || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0 $TEST_JSN_SIZE
	jq -c --arg koff $KEYSLOTS_OFFSET --arg jsize $JSON_SIZE \
		'if ([.keyslots[].area.offset] | map(tonumber) | min | tostring != $koff) or
		    (.config.json_size != $jsize)
		then error("Unexpected value in result json") else empty end' $TMPDIR/json_res0 || exit 5
}

lib_prepare $@
generate
check
lib_cleanup
