#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate header with bad checksum in secondary binary header
#

# $1 full target dir
# $2 full source luks2 image

function prepare()
{
	cp $SRC_IMG $TGT_IMG
	test -d tmp || mkdir tmp
	read_luks2_bin_hdr1 $TGT_IMG tmp/hdr1
}

function generate()
{
	chks=$(echo "Arbitrary chosen string: D'oh!" | calc_sha256_checksum_stdin)
	write_checksum $chks tmp/hdr1
	write_luks2_bin_hdr1 tmp/hdr1 $TGT_IMG
}

function check()
{
	chks_res=$(read_sha256_checksum tmp/hdr1)
	test "$chks" = "$chks_res" || exit 2
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
