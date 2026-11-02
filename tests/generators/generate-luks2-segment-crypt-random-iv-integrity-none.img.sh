#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with segment using random IV and integrity type "none"
# (per-sector metadata would contain unauthenticated IV only)
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

generate()
{
	# random IV stored in per-sector metadata must be authenticated
	json_str=$(_jq '.segments."0".encryption = "aes-xts-random" |
			.segments."0".integrity = { type: "none", journal_encryption: "none", journal_integrity: "none" }' $TMPDIR/json0)
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	write_luks2_json "$json_str" $TMPDIR/json0

	lib_mangle_json_hdr0_kill_hdr1
}

check()
{
	lib_hdr1_killed || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	_jq 'if (.segments."0".encryption != "aes-xts-random") or (.segments."0".integrity.type != "none")
	       then error("Unexpected value in result json") else empty end' $TMPDIR/json_res0 || exit 5
}

lib_prepare $@
generate
check
lib_cleanup
