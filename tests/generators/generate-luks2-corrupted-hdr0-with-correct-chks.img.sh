#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate header with malformed json but correct checksum in primary header
#

# $1 full target dir
# $2 full source luks2 image

generate()
{
	read -r json_str < $TMPDIR/json0
	json_len=${#json_str}
	json_len=$((json_len-1)) # to replace json closing '}'
	json_new_str="${json_str:0:json_len},\""

	while [ ${#json_new_str} -le $((LUKS2_JSON_SIZE*512)) ]; do
		json_new_str=$json_new_str"all_work_and_no_play_makes_Jack_a_dull_boy_"
	done

	printf "%s" $json_new_str | _dd of=$TMPDIR/json0 bs=512 count=$LUKS2_JSON_SIZE

	lib_mangle_json_hdr0
}

check()
{
	lib_hdr0_checksum || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	read -r json_str_res0 < $TMPDIR/json_res0
	test ${#json_str_res0} -eq $((LUKS2_JSON_SIZE*512)) || exit 2
}

lib_prepare $@
generate
check
lib_cleanup
