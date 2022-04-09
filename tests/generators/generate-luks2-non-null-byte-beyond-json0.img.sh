#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with json area concluded with illegal
# byte beyond terminating '}' character.
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

function generate()
{
	read -r json_str < $TMPDIR/json0
	json_str="$json_str"X # add illegal 'X' beyond json format
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	printf '%s' $json_str | _dd of=$TMPDIR/json0 bs=1 conv=notrunc

	lib_mangle_json_hdr0_kill_hdr1
}

function check()
{
	read_luks2_bin_hdr1 $TGT_IMG $TMPDIR/hdr_res1
	local str_res1=$(head -c 6 $TMPDIR/hdr_res1)
	test "$str_res1" = "VACUUM" || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	chks_res0=$(read_sha256_checksum $TGT_IMG)
	test "$chks0" = "$chks_res0" || exit 2
	read -r json_str_res0 < $TMPDIR/json_res0
	local len=${#json_str_res0}
	len=$((len-1))
	test ${json_str_res0:len:1} = "X" || exit 2
}

lib_prepare $@
generate
check
lib_cleanup
