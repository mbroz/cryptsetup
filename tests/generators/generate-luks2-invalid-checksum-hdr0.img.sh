#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate header with bad checksum in primary binary header
#

# 1 full target dir
# 2 full source luks2 image

generate()
{
	CHKS0=$(echo "Arbitrary chosen string: D'oh!" | calc_sha256_checksum_stdin)
	write_checksum $CHKS0 $TGT_IMG
}

check()
{
	lib_hdr0_checksum || exit 2
}

lib_prepare $@
generate
check
lib_cleanup
