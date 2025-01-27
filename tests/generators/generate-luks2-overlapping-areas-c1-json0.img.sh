#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with one area included within another one (in terms of 'offset' + 'length')
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

generate()
{
	# make area 7 being included in area 6
	json_str=$(jq -c '.keyslots."7".area.offset = (.keyslots."6".area.offset | tonumber + 1 | tostring ) |
	       .keyslots."7".area.size = ( .keyslots."6".area.size | tonumber - 1 | tostring)' $TMPDIR/json0)
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	write_luks2_json "$json_str" $TMPDIR/json0

	lib_mangle_json_hdr0_kill_hdr1
}

check()
{
	lib_hdr1_killed || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	jq -c 'if (.keyslots."7".area.offset != (.keyslots."6".area.offset | tonumber + 1 | tostring)) or
		  (.keyslots."7".area.size != (.keyslots."6".area.size | tonumber - 1 | tostring)) or
		  (.keyslots."7".area.size | tonumber <= 0)
	       then error("Unexpected value in result json") else empty end' $TMPDIR/json_res0 || exit 5
}

lib_prepare $@
generate
check
lib_cleanup
