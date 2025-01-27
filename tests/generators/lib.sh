#!/bin/bash

# all in 512 bytes blocks (including binary hdr (4KiB))
LUKS2_HDR_SIZE=32		#  16 KiB
LUKS2_HDR_SIZE_32K=64		#  32 KiB
LUKS2_HDR_SIZE_64K=128		#  64 KiB
LUKS2_HDR_SIZE_128K=256		# 128 KiB
LUKS2_HDR_SIZE_256K=512		# 256 KiB
LUKS2_HDR_SIZE_512K=1024	# 512 KiB
LUKS2_HDR_SIZE_1M=2048		#   1 MiB
LUKS2_HDR_SIZE_2M=4096		#   2 MiB
LUKS2_HDR_SIZE_4M=8192		#   4 MiB

LUKS2_BIN_HDR_SIZE=8		#   4 KiB
LUKS2_JSON_SIZE=$((LUKS2_HDR_SIZE-LUKS2_BIN_HDR_SIZE))

LUKS2_BIN_HDR_CHKS_OFFSET=0x1C0
LUKS2_BIN_HDR_CHKS_LENGTH=64

[ -z "$srcdir" ] && srcdir="."
TMPDIR=$srcdir/tmp

# to be set by individual generator
TGT_IMG=""
SRC_IMG=""

repeat_str() {
	printf "$1"'%.0s' $(eval "echo {1.."$(($2))"}");
}

strindex()
{
	local x="${1%%$2*}"
	[[ $x = $1 ]] && echo -1 || echo ${#x}
}

test_img_name()
{
	local str=$(basename $1)
	str=${str#generate-}
	str=${str%%.sh}
	echo $str
}

# read primary bin hdr
# 1:from 2:to
read_luks2_bin_hdr0()
{
	_dd if=$1 of=$2 bs=512 count=$LUKS2_BIN_HDR_SIZE
}

# read primary json area
# 1:from 2:to 3:[json only size (defaults to 12KiB)]
read_luks2_json0()
{
	local _js=${4:-$LUKS2_JSON_SIZE}
	local _js=$((_js*512/4096))
	_dd if=$1 of=$2 bs=4096 skip=1 count=$_js
}

# read secondary bin hdr
# 1:from 2:to 3:[metadata size (defaults to 16KiB)]
read_luks2_bin_hdr1()
{
	_dd if=$1 of=$2 skip=${3:-$LUKS2_HDR_SIZE} bs=512 count=$LUKS2_BIN_HDR_SIZE
}

# read secondary json area
# 1:from 2:to 3:[json only size (defaults to 12KiB)]
read_luks2_json1()
{
	local _js=${3:-$LUKS2_JSON_SIZE}
	_dd if=$1 of=$2 bs=512 skip=$((2*LUKS2_BIN_HDR_SIZE+_js)) count=$_js
}

# read primary metadata area (bin + json)
# 1:from 2:to 3:[metadata size (defaults to 16KiB)]
read_luks2_hdr_area0()
{
	local _as=${3:-$LUKS2_HDR_SIZE}
	local _as=$((_as*512))
	_dd if=$1 of=$2 bs=$_as count=1
}

# read secondary metadata area (bin + json)
# 1:from 2:to 3:[metadata size (defaults to 16KiB)]
read_luks2_hdr_area1()
{
	local _as=${3:-$LUKS2_HDR_SIZE}
	local _as=$((_as*512))
	_dd if=$1 of=$2 bs=$_as skip=1 count=1
}

# write secondary bin hdr
# 1:from 2:to 3:[metadata size (defaults to 16KiB)]
write_luks2_bin_hdr1()
{
	_dd if=$1 of=$2 bs=512 seek=${3:-$LUKS2_HDR_SIZE} count=$LUKS2_BIN_HDR_SIZE conv=notrunc
}

# write primary metadata area (bin + json)
# 1:from 2:to 3:[metadata size (defaults to 16KiB)]
write_luks2_hdr0()
{
	local _as=${3:-$LUKS2_HDR_SIZE}
	local _as=$((_as*512))
	_dd if=$1 of=$2 bs=$_as count=1 conv=notrunc
}

# write secondary metadata area (bin + json)
# 1:from 2:to 3:[metadata size (defaults to 16KiB)]
write_luks2_hdr1()
{
	local _as=${3:-$LUKS2_HDR_SIZE}
	local _as=$((_as*512))
	_dd if=$1 of=$2 bs=$_as seek=1 count=1 conv=notrunc
}

# write json (includes padding)
# 1:json_string 2:to 3:[json size (defaults to 12KiB)]
write_luks2_json()
{
	local _js=${3:-$LUKS2_JSON_SIZE}
	local len=${#1}
	echo -n -E "$1" > $2
	truncate -s $((_js*512)) $2
}

kill_bin_hdr()
{
	printf "VACUUM" | _dd of=$1 bs=1 conv=notrunc
}

erase_checksum()
{
	_dd if=/dev/zero of=$1 bs=1 seek=$(printf %d $LUKS2_BIN_HDR_CHKS_OFFSET) count=$LUKS2_BIN_HDR_CHKS_LENGTH conv=notrunc
}

read_sha256_checksum()
{
	_dd if=$1 bs=1 skip=$(printf %d $LUKS2_BIN_HDR_CHKS_OFFSET) count=32 | xxd -c 32 -p
}

# 1 - string with checksum
write_checksum()
{
	test $# -eq 2 || return 1
	test $((${#1}/2)) -le $LUKS2_BIN_HDR_CHKS_LENGTH || { echo "too long"; return 1; }

	echo $1 | xxd -r -p | _dd of=$2 bs=1 seek=$(printf %d $LUKS2_BIN_HDR_CHKS_OFFSET) conv=notrunc
}

calc_sha256_checksum_file()
{
	sha256sum $1 | cut -d ' ' -f 1
}

calc_sha256_checksum_stdin()
{
	sha256sum - | cut -d ' ' -f 1
}

# merge bin hdr with json to form metadata area
# 1:bin_hdr 2:json 3:to 4:[json size (defaults to 12KiB)]
merge_bin_hdr_with_json()
{
	local _js=${4:-$LUKS2_JSON_SIZE}
	local _js=$((_js*512/4096))
	_dd if=$1 of=$3 bs=4096 count=1
	_dd if=$2 of=$3 bs=4096 seek=1 count=$_js
}

_dd()
{
	dd $@ status=none
}

write_bin_hdr_size() {
	printf '%016x' $2 | xxd -r -p -l 16 | _dd of=$1 bs=8 count=1 seek=1 conv=notrunc
}

write_bin_hdr_offset() {
	printf '%016x' $2 | xxd -r -p -l 16 | _dd of=$1 bs=8 count=1 seek=32 conv=notrunc
}

# generic header helpers
# $TMPDIR/json0 - JSON hdr1
# $TMPDIR/json1 - JSON hdr2
# $TMPDIR/hdr0  - bin hdr1
# $TMPDIR/hdr1  - bin hdr2

# 1:target_dir 2:source_image
lib_prepare()
{
	test $# -eq 2 || exit 1

	TGT_IMG=$1/$(test_img_name $0)
	SRC_IMG=$2

	# wipe checksums
	CHKS0=0
	CHKS1=0

	cp $SRC_IMG $TGT_IMG
	test -d $TMPDIR || mkdir $TMPDIR
	read_luks2_json0 $TGT_IMG $TMPDIR/json0
	read_luks2_json1 $TGT_IMG $TMPDIR/json1
	read_luks2_bin_hdr0 $TGT_IMG $TMPDIR/hdr0
	read_luks2_bin_hdr1 $TGT_IMG $TMPDIR/hdr1
}

lib_cleanup()
{
	rm -f $TMPDIR/*
	rm -fd $TMPDIR
}

lib_mangle_json_hdr0()
{
	local mda_sz=${1:-}
	local jsn_sz=${2:-}
	local kill_hdr=${3:-}

	merge_bin_hdr_with_json $TMPDIR/hdr0 $TMPDIR/json0 $TMPDIR/area0 $jsn_sz
	erase_checksum $TMPDIR/area0
	CHKS0=$(calc_sha256_checksum_file $TMPDIR/area0)
	write_checksum $CHKS0 $TMPDIR/area0
	test -n "$kill_hdr" && kill_bin_hdr $TMPDIR/area0
	write_luks2_hdr0 $TMPDIR/area0 $TGT_IMG $mda_sz
}

lib_mangle_json_hdr1()
{
	local mda_sz=${1:-}
	local jsn_sz=${2:-}
	local kill_hdr=${3:-}

	merge_bin_hdr_with_json $TMPDIR/hdr1 $TMPDIR/json1 $TMPDIR/area1 $jsn_sz
	erase_checksum $TMPDIR/area1
	CHKS1=$(calc_sha256_checksum_file $TMPDIR/area1)
	write_checksum $CHKS1 $TMPDIR/area1
	test -n "$kill_hdr" && kill_bin_hdr $TMPDIR/area1
	write_luks2_hdr1 $TMPDIR/area1 $TGT_IMG $mda_sz
}

lib_mangle_json_hdr0_kill_hdr1()
{
	lib_mangle_json_hdr0

	kill_bin_hdr $TMPDIR/hdr1
	write_luks2_hdr1 $TMPDIR/hdr1 $TGT_IMG
}

lib_hdr0_killed()
{
	local mda_sz=${1:-}

	read_luks2_bin_hdr0 $TGT_IMG $TMPDIR/hdr_res0 $mda_sz
	local str_res0=$(head -c 6 $TMPDIR/hdr_res0)
	test "$str_res0" = "VACUUM"
}

lib_hdr1_killed()
{
	local mda_sz=${1:-}

	read_luks2_bin_hdr1 $TGT_IMG $TMPDIR/hdr_res1 $mda_sz
	local str_res1=$(head -c 6 $TMPDIR/hdr_res1)
	test "$str_res1" = "VACUUM"
}

lib_hdr0_checksum()
{
	local chks_res0=$(read_sha256_checksum $TGT_IMG)
	test "$CHKS0" = "$chks_res0"
}

lib_hdr1_checksum()
{
	read_luks2_bin_hdr1 $TGT_IMG $TMPDIR/hdr_res1
	local chks_res1=$(read_sha256_checksum $TMPDIR/hdr_res1)
	test "$CHKS1" = "$chks_res1"
}
