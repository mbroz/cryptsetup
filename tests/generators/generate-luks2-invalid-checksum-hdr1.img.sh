#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate header with bad checksum in secondary binary header
#

# $1 full target dir
# $2 full source luks2 image

function generate()
{
	chks=$(echo "Arbitrary chosen string: D'oh!" | calc_sha256_checksum_stdin)
	write_checksum $chks $TMPDIR/hdr1
	write_luks2_bin_hdr1 $TMPDIR/hdr1 $TGT_IMG
}

function check()
{
	chks_res=$(read_sha256_checksum $TMPDIR/hdr1)
	test "$chks" = "$chks_res" || exit 2
}

lib_prepare $@
generate
check
lib_cleanup
