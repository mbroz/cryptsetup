#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with missing keyslot object referenced
# in digest object
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

generate()
{
	read -r json_str_orig < $TMPDIR/json0
	arr_len=$(jq -c -M '.digests."0".keyslots | length' $TMPDIR/json0)
	# add missing keyslot reference in keyslots array of digest '0'
	json_str=$(jq -r -c -M 'def arr: ["digests", "0", "keyslots"];
	       def missks: getpath(["keyslots"]) | keys | max | tonumber + 1 | tostring;
	       setpath(arr; getpath(arr) + [ missks ])' $TMPDIR/json0)
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	write_luks2_json "$json_str" $TMPDIR/json0

	lib_mangle_json_hdr0_kill_hdr1
}

check()
{
	lib_hdr1_killed || exit 2
	lib_hdr0_checksum || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	new_arr_len=$(jq -c -M '.digests."0".keyslots | length' $TMPDIR/json_res0)
	test $((arr_len+1)) -eq $new_arr_len || exit 2
}

lib_prepare $@
generate
check
lib_cleanup
