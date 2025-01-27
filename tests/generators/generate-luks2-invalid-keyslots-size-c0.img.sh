#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with too large keyslots_size set in config section
# (iow config.keyslots_size = data_offset - keyslots_offset + 512)
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

generate()
{
	# make area 7 being included in area 6
	OFFS=$((2*LUKS2_HDR_SIZE*512))
	json_str=$(jq -c --arg off $OFFS '.config.keyslots_size = (.segments."0".offset | tonumber - ($off | tonumber) + 4096 | tostring)' $TMPDIR/json0)
	test -n "$json_str" || exit 2
	# [.keyslots[].area.offset | tonumber] | max | tostring ---> max offset in keyslot areas
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	write_luks2_json "$json_str" $TMPDIR/json0

	lib_mangle_json_hdr0_kill_hdr1
}

check()
{
	lib_hdr1_killed || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	jq -c --arg off $OFFS 'if .config.keyslots_size != ( .segments."0".offset | tonumber - ($off | tonumber) + 4096 | tostring )
	       then error("Unexpected value in result json") else empty end' $TMPDIR/json_res0 || exit 5
}

lib_prepare $@
generate
check
lib_cleanup
