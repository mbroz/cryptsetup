#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with wrong backup segment id
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

generate()
{
	# create illegal backup segment key (used to be bug in 32bit implementations)
	json_str=$(jq -c '(.segments."0".offset | tonumber) as $i | .segments[range(1;65) | tostring] = { "type" : "linear", "offset" : ($i + 512 | tostring), "size" : "512" } | .segments."268435472" = { "type":"linear","offset":"512","size":"512","flags":["backup-x"]}' $TMPDIR/json0)
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	write_luks2_json "$json_str" $TMPDIR/json0

	lib_mangle_json_hdr0_kill_hdr1
}

check()
{
	lib_hdr1_killed || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	jq -c 'if .segments | length < 64
	       then error("Unexpected segments count") else empty end' $TMPDIR/json_res0 || exit 5
}

lib_prepare $@
generate
check
lib_cleanup
