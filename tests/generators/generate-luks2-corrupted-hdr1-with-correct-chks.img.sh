#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate header with malformed json but correct checksum in secondary header
#

# $1 full target dir
# $2 full source luks2 image

function prepare()
{
	cp $SRC_IMG $TGT_IMG
	test -d tmp || mkdir tmp
	read_luks2_json1 $TGT_IMG tmp/json1
	read_luks2_bin_hdr1 $TGT_IMG tmp/hdr1
}

function generate()
{
	json_str=$(< tmp/json1)
	json_len=${#json_str}
	json_len=$((json_len-1)) # to replace json closing '}'
	json_new_str="${json_str:0:json_len},\""

	while [ ${#json_new_str} -le $((LUKS2_JSON_SIZE*512)) ]; do
		json_new_str=$json_new_str"all_work_and_no_play_makes_Jack_a_dull_boy_"
	done

	printf "%s" $json_new_str | _dd of=tmp/json1 bs=512 count=$LUKS2_JSON_SIZE

	merge_bin_hdr_with_json tmp/hdr1 tmp/json1 tmp/area1
	erase_checksum tmp/area1
	chks1=$(calc_sha256_checksum_file tmp/area1)
	write_checksum $chks1 tmp/area1
	write_luks2_hdr1 tmp/area1 $TGT_IMG
}

function check()
{
	read_luks2_bin_hdr1 $TGT_IMG tmp/hdr_res1
	chks_res1=$(read_sha256_checksum tmp/hdr_res1)
	test "$chks1" = "$chks_res1" || exit 2
	read_luks2_json1 $TGT_IMG tmp/json_res1
	json_str_res1=$(< tmp/json_res1)
	test ${#json_str_res1} -eq $((LUKS2_JSON_SIZE*512)) || exit 2
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
