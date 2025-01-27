#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with invalid json_size in config section
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

generate()
{
	JS=$(((LUKS2_HDR_SIZE-LUKS2_BIN_HDR_SIZE)*512-4096))
	json_str=$(jq -c --arg js $JS '.config.json_size = ($js | tostring)' $TMPDIR/json0)
	test -n "$json_str" || exit 2
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	write_luks2_json "$json_str" $TMPDIR/json0

	lib_mangle_json_hdr0_kill_hdr1
}

check()
{
	lib_hdr1_killed || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	jq -c --arg js $JS 'if .config.json_size != ($js | tostring )
	       then error("Unexpected value in result json") else empty end' $TMPDIR/json_res0 || exit 5
}

lib_prepare $@
generate
check
lib_cleanup
