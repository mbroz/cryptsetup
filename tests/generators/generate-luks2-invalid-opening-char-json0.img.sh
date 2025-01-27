#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with well-formed json prefixed
# with useless whitespace.
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

generate()
{
	read -r json_str < $TMPDIR/json0
	json_str=" $json_str" # add useless opening whitespace
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	printf "%s" "$json_str" | _dd of=$TMPDIR/json0 bs=1 conv=notrunc

	lib_mangle_json_hdr0_kill_hdr1
}

check()
{
	lib_hdr1_killed || exit 2
	lib_hdr0_checksum || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	IFS= read -r json_str_res0 < $TMPDIR/json_res0
	test "$json_str" = "$json_str_res0" || exit 2
}

lib_prepare $@
generate
check
lib_cleanup
