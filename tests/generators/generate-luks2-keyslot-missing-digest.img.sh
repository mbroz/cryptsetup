#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with luks2 keyslot not assigned
# to any digest.
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

function generate()
{
	read -r json_str_orig < $TMPDIR/json0
	arr_len=$(jq -c -M '.digests."0".keyslots | length' $TMPDIR/json0)
	# remove first element from digests."0".keyslots array
	json_str=$(jq -r -c -M 'del(.digests."0".keyslots[0])' $TMPDIR/json0)
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	write_luks2_json "$json_str" $TMPDIR/json0

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
	new_arr_len=$(jq -c -M '.digests."0".keyslots | length' $TMPDIR/json_res0)
	test $((arr_len-1)) -eq $new_arr_len || exit 2
}

lib_prepare $@
generate
check
lib_cleanup
