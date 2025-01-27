#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with missing keyslot object referenced
# in token object
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

generate()
{
	read -r json_str_orig < $TMPDIR/json0
	# add missing keyslot reference in keyslots array of token '0'
	json_str=$(jq -r -c -M 'def missks: getpath(["keyslots"]) | keys | max | tonumber + 1 | tostring;
	      .tokens += {"0":{"type":"dummy","keyslots":[ "0", missks ]}}' $TMPDIR/json0)
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	write_luks2_json "$json_str" $TMPDIR/json0

	lib_mangle_json_hdr0_kill_hdr1
}

check()
{
	lib_hdr1_killed || exit 2
	lib_hdr0_checksum || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	new_arr_len=$(jq -c -M '.tokens."0".keyslots | length' $TMPDIR/json_res0)
	test $new_arr_len -eq 2 || exit 2
}

lib_prepare $@
generate
check
lib_cleanup
