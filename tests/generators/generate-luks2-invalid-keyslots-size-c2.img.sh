#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with keyslots_size less than sum of all keyslots area
# in json
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

generate()
{
	json_str=$(jq '.config.keyslots_size = ([.keyslots[].area.size] | map(tonumber) | add - 4096 | tostring )' $TMPDIR/json0)
	test -n "$json_str" || exit 2
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	write_luks2_json "$json_str" $TMPDIR/json0

	lib_mangle_json_hdr0_kill_hdr1
}

check()
{
	lib_hdr1_killed || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	jq -c 'if .config.keyslots_size != ([.keyslots[].area.size ] | map(tonumber) | add - 4096 | tostring)
	       then error("Unexpected value in result json") else empty end' $TMPDIR/json_res0 || exit 5
}

lib_prepare $@
generate
check
lib_cleanup
