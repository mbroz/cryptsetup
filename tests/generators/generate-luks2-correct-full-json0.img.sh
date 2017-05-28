#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate header with correct json of maximal size in primary slot.
# Secondary header is broken on purpose.
#

# $1 full target dir
# $2 full source luks2 image

PATTERN="\"config\":{"
KEY="\"config_key\":\""

function prepare()
{
	cp $SRC_IMG $TGT_IMG
	test -d $TMPDIR || mkdir $TMPDIR
	read_luks2_json0 $TGT_IMG $TMPDIR/json0
	read_luks2_bin_hdr0 $TGT_IMG $TMPDIR/hdr0
	read_luks2_bin_hdr1 $TGT_IMG $TMPDIR/hdr1
}

function generate()
{
	read -r json_str < $TMPDIR/json0
	json_len=${#json_str}
	pindex=$(strindex $json_str $PATTERN)
	test $pindex -gt 0 || exit 2

	offset=${#PATTERN}
	offset=$((offset+pindex))
	key_len=${#KEY}
	remain=$((LUKS2_JSON_SIZE*512-json_len-key_len-2)) # -2: closing '"' and terminating '\0'
	if [ ${json_str:offset:1} = "}" ]; then
		format_str="%s%s%s"
	else
		format_str="%s%s,%s"
		remain=$((remain-1)) # also count with separating ','
	fi
	test $remain -gt 0 || exit 2

	fill=$(repeat_str "X" $remain)"\""

	printf $format_str $KEY $fill ${json_str:$offset} | _dd of=$TMPDIR/json0 bs=1 seek=$offset conv=notrunc

	merge_bin_hdr_with_json $TMPDIR/hdr0 $TMPDIR/json0 $TMPDIR/area0
	erase_checksum $TMPDIR/area0
	chks0=$(calc_sha256_checksum_file $TMPDIR/area0)
	write_checksum $chks0 $TMPDIR/area0
	write_luks2_hdr0 $TMPDIR/area0 $TGT_IMG
	kill_bin_hdr $TMPDIR/hdr1
	write_luks2_hdr1 $TMPDIR/hdr1 $TGT_IMG
}

function check()
{
	read_luks2_bin_hdr1 $TGT_IMG $TMPDIR/hdr_res1
	local str_res1=$(head -c 6 $TMPDIR/hdr_res1)
	test "$str_res1" = "VACUUM" || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	chks_res0=$(read_sha256_checksum $TGT_IMG)
	test "$chks0" = "$chks_res0" || exit 2
	#json_str_res0=$(< $TMPDIR/json_res0)
	read -r json_str_res0 < $TMPDIR/json_res0
	test ${#json_str_res0} -eq $((LUKS2_JSON_SIZE*512-1)) || exit 2
}

function cleanup()
{
	rm -f $TMPDIR/*
	rm -fd $TMPDIR
}

test $# -eq 2 || exit 1

TGT_IMG=$1/$(test_img_name $0)
SRC_IMG=$2

prepare
generate
check
cleanup
