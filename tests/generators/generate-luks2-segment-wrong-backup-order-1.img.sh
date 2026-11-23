#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with regular segment behind backup segment
# (the regular segment is stored first in the segments object)
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

generate()
{
	# the check must not depend on order of keys in json text
	json_str=$(_jq '.segments = { "2" : { "type":"linear","offset":.segments."0".offset,"size":"512" }, "0" : .segments."0", "1" : { "type":"linear","offset":"512","size":"512","flags":["backup-x"]}}' $TMPDIR/json0)
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	write_luks2_json "$json_str" $TMPDIR/json0

	lib_mangle_json_hdr0_kill_hdr1
}

check()
{
	lib_hdr1_killed || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	_jq 'if (.segments | keys_unsorted) != ["2","0","1"]
	       then error("Unexpected segments order") else empty end' $TMPDIR/json_res0 || exit 5
}

lib_prepare $@
generate
check
lib_cleanup
