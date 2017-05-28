#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate header with bad checksum in primary binary header
#

# 1 full target dir
# 2 full source luks2 image

function prepare()
{
	cp $SRC_IMG $TGT_IMG
}

function generate()
{
	chks=$(echo "Arbitrary chosen string: D'oh!" | calc_sha256_checksum_stdin)
	write_checksum $chks $TGT_IMG
}

function check()
{
	chks_res=$(read_sha256_checksum $TGT_IMG)
	test "$chks" = "$chks_res" || exit 2
}

#function cleanup()
#{
#}

test $# -eq 2 || exit 1

TGT_IMG=$1/$(test_img_name $0)
SRC_IMG=$2

prepare
generate
check
#cleanup
