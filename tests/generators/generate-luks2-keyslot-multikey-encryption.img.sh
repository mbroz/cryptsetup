#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate header with keyslot area encryption selecting
# dm-crypt multi-key mode (cipher:keycount-mode-iv notation)
#

# $1 full target dir
# $2 full source luks2 image

generate()
{
	json_str=$(_jq '.keyslots."0".area.encryption = "serpent:64-ecb"' $TMPDIR/json0)
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	write_luks2_json "$json_str" $TMPDIR/json0
	write_luks2_json "$json_str" $TMPDIR/json1

	lib_mangle_json_hdr0
	lib_mangle_json_hdr1
}

check()
{
	lib_hdr0_checksum || exit 2
	lib_hdr1_checksum || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	_jq 'if .keyslots."0".area.encryption != "serpent:64-ecb"
	       then error("Unexpected value in result json") else empty end' $TMPDIR/json_res0 || exit 5
}

lib_prepare $@
generate
check
lib_cleanup
