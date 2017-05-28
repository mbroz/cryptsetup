#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate header with bad checksum in both binary headerer
#

# $1 full target dir
# $2 full source luks2 image

function prepare()
{
	cp $SRC_IMG $TGT_IMG
	test -d $TMPDIR || mkdir $TMPDIR
	read_luks2_bin_hdr1 $TGT_IMG $TMPDIR/hdr1
}

function generate()
{
	chks0=$(echo "Arbitrary chosen string: D'oh!" | calc_sha256_checksum_stdin)
	chks1=$(echo "D'oh!: arbitrary chosen string" | calc_sha256_checksum_stdin)
	write_checksum $chks0 $TGT_IMG
	write_checksum $chks1 $TMPDIR/hdr1
	write_luks2_bin_hdr1 $TMPDIR/hdr1 $TGT_IMG
}

function check()
{
	chks_res0=$(read_sha256_checksum $TGT_IMG)
	chks_res1=$(read_sha256_checksum $TMPDIR/hdr1)
	test "$chks0" = "$chks_res0" || exit 2
	test "$chks1" = "$chks_res1" || exit 2
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
