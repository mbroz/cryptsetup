#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with 5th area having keyslots array with value
# referencing non existent keyslot object
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

function prepare()
{
	cp $SRC_IMG $TGT_IMG
	test -d tmp || mkdir tmp
	read_luks2_json0 $TGT_IMG tmp/json0
	read_luks2_bin_hdr0 $TGT_IMG tmp/hdr0
	read_luks2_bin_hdr1 $TGT_IMG tmp/hdr1
}

function generate()
{
	json_str_orig="$(< tmp/json0)"
	# add missing keyslot reference in keyslots array of area indexed by 4
	json_str=$(jq -c 'def arr: ["areas", "4", "keyslots"];
               def missks: getpath(["keyslots"]) | keys | max | tonumber + 1 | tostring;
	       setpath(arr; getpath(arr) + [ missks ])' tmp/json0)
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2
	test ${#json_str_orig} -lt ${#json_str} || exit 2

	write_luks2_json "$json_str" tmp/json0

	merge_bin_hdr_with_json tmp/hdr0 tmp/json0 tmp/area0
	erase_checksum tmp/area0
	chks0=$(calc_sha256_checksum_file tmp/area0)
	write_checksum $chks0 tmp/area0
	write_luks2_hdr0 tmp/area0 $TGT_IMG
	kill_bin_hdr tmp/hdr1
	write_luks2_hdr1 tmp/hdr1 $TGT_IMG
}

function check()
{
	read_luks2_bin_hdr1 $TGT_IMG tmp/hdr_res1
	local str_res1=$(head -c 6 tmp/hdr_res1)
	test "$str_res1" = "VACUUM" || exit 2

	read_luks2_json0 $TGT_IMG tmp/json_res0
	chks_res0=$(read_sha256_checksum $TGT_IMG)
	test "$chks0" = "$chks_res0" || exit 2
	json_str_res0=$(< tmp/json_res0)
	test "$json_str" = "$json_str_res0" || exit 2
}

function cleanup()
{
	rm -f tmp/*
}

test $# -eq 2 || exit 1

TGT_IMG=$1/$(test_img_name $0)
SRC_IMG=$2

prepare
generate
check
cleanup
