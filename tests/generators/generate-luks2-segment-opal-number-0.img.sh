#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with hw-opal-crypt segment
# referencing the OPAL global locking range (0)
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

generate()
{
	# LUKS2 never uses global locking range 0
	json_str=$(_jq '.segments."0".type = "hw-opal-crypt" |
			.segments."0".size = "16777216" |
			.segments."0".opal_segment_number = 0 |
			.segments."0".opal_key_size = 32 |
			.segments."0".opal_segment_size = "16777216"' $TMPDIR/json0)
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	write_luks2_json "$json_str" $TMPDIR/json0

	lib_mangle_json_hdr0_kill_hdr1
}

check()
{
	lib_hdr1_killed || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	_jq 'if .segments."0".opal_segment_number != 0
	       then error("Unexpected value in result json") else empty end' $TMPDIR/json_res0 || exit 5
}

lib_prepare $@
generate
check
lib_cleanup
