#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate header with bad checksum in secondary binary header
#

# $1 full target dir
# $2 full source luks2 image

generate()
{
	CHKS1=$(echo "Arbitrary chosen string: D'oh!" | calc_sha256_checksum_stdin)
	write_checksum $CHKS1 $TMPDIR/hdr1
	write_luks2_bin_hdr1 $TMPDIR/hdr1 $TGT_IMG
}

check()
{
	lib_hdr1_checksum || exit 2
}

lib_prepare $@
generate
check
lib_cleanup
