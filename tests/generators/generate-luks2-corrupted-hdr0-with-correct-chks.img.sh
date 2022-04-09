#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate header with malformed json but correct checksum in primary header
#

# $1 full target dir
# $2 full source luks2 image

function generate()
{
	read -r json_str < $TMPDIR/json0
	json_len=${#json_str}
	json_len=$((json_len-1)) # to replace json closing '}'
	json_new_str="${json_str:0:json_len},\""

	while [ ${#json_new_str} -le $((LUKS2_JSON_SIZE*512)) ]; do
		json_new_str=$json_new_str"all_work_and_no_play_makes_Jack_a_dull_boy_"
	done

	printf "%s" $json_new_str | _dd of=$TMPDIR/json0 bs=512 count=$LUKS2_JSON_SIZE

	merge_bin_hdr_with_json $TMPDIR/hdr0 $TMPDIR/json0 $TMPDIR/area0
	erase_checksum $TMPDIR/area0
	chks0=$(calc_sha256_checksum_file $TMPDIR/area0)
	write_checksum $chks0 $TMPDIR/area0
	write_luks2_hdr0 $TMPDIR/area0 $TGT_IMG
}

function check()
{
	chks_res0=$(read_sha256_checksum $TGT_IMG)
	test "$chks0" = "$chks_res0" || exit 2
	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	read -r json_str_res0 < $TMPDIR/json_res0
	test ${#json_str_res0} -eq $((LUKS2_JSON_SIZE*512)) || exit 2
}

function cleanup()
{
	rm -f $TMPDIR/*
	rm -fd $TMPDIR
}

lib_prepare $@
generate
check
cleanup
