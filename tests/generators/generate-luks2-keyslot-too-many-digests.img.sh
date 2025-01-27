#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with luks2 keyslot assigned
# to more than 1 digest.
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

generate()
{
	# add keyslot 1 to second digest
	json_str=$(jq -r -c -M '.digests."1" = .digests."0" | .digests."1".keyslots = ["1"]' $TMPDIR/json0)
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	write_luks2_json "$json_str" $TMPDIR/json0

	lib_mangle_json_hdr0_kill_hdr1
}

check()
{
	lib_hdr1_killed || exit 2
	lib_hdr0_checksum || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	new_arr_len=$(jq -c -M '.digests."1".keyslots | length' $TMPDIR/json_res0)
	test 1 -eq $new_arr_len || exit 2
}

lib_prepare $@
generate
check
lib_cleanup
