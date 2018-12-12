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

repeat_str() {
	printf "$1"'%.0s' $(eval "echo {1.."$(($2))"}");
}

function strindex()
{
	local x="${1%%$2*}"
	[[ $x = $1 ]] && echo -1 || echo ${#x}
}

function test_img_name()
{
	local str=$(basename $1)
	str=${str#generate-}
	str=${str%%.sh}
	echo $str
}

# read primary bin hdr
# 1:from 2:to
function read_luks2_bin_hdr0()
{
	_dd if=$1 of=$2 bs=512 count=$LUKS2_BIN_HDR_SIZE
}

# read primary json area
# 1:from 2:to 3:[json only size (defaults to 12KiB)]
function read_luks2_json0()
{
	local _js=${4:-$LUKS2_JSON_SIZE}
	local _js=$((_js*512/4096))
	_dd if=$1 of=$2 bs=4096 skip=1 count=$_js
}

# read secondary bin hdr
# 1:from 2:to 3:[metadata size (defaults to 16KiB)]
function read_luks2_bin_hdr1()
{
	_dd if=$1 of=$2 skip=${3:-$LUKS2_HDR_SIZE} bs=512 count=$LUKS2_BIN_HDR_SIZE
}

# read secondary json area
# 1:from 2:to 3:[json only size (defaults to 12KiB)]
function read_luks2_json1()
{
	local _js=${3:-$LUKS2_JSON_SIZE}
	_dd if=$1 of=$2 bs=512 skip=$((2*LUKS2_BIN_HDR_SIZE+_js)) count=$_js
}

# read primary metadata area (bin + json)
# 1:from 2:to 3:[metadata size (defaults to 16KiB)]
function read_luks2_hdr_area0()
{
	local _as=${3:-$LUKS2_HDR_SIZE}
	local _as=$((_as*512))
	_dd if=$1 of=$2 bs=$_as count=1
}

# read secondary metadata area (bin + json)
# 1:from 2:to 3:[metadata size (defaults to 16KiB)]
function read_luks2_hdr_area1()
{
	local _as=${3:-$LUKS2_HDR_SIZE}
	local _as=$((_as*512))
	_dd if=$1 of=$2 bs=$_as skip=1 count=1
}

# write secondary bin hdr
# 1:from 2:to 3:[metadata size (defaults to 16KiB)]
function write_luks2_bin_hdr1()
{
	_dd if=$1 of=$2 bs=512 seek=${3:-$LUKS2_HDR_SIZE} count=$LUKS2_BIN_HDR_SIZE conv=notrunc
}

# write primary metadata area (bin + json)
# 1:from 2:to 3:[metadata size (defaults to 16KiB)]
function write_luks2_hdr0()
{
	local _as=${3:-$LUKS2_HDR_SIZE}
	local _as=$((_as*512))
	_dd if=$1 of=$2 bs=$_as count=1 conv=notrunc
}

# write secondary metadata area (bin + json)
# 1:from 2:to 3:[metadata size (defaults to 16KiB)]
function write_luks2_hdr1()
{
	local _as=${3:-$LUKS2_HDR_SIZE}
	local _as=$((_as*512))
	_dd if=$1 of=$2 bs=$_as seek=1 count=1 conv=notrunc
}

# write json (includes padding)
# 1:json_string 2:to 3:[json size (defaults to 12KiB)]
function write_luks2_json()
{
	local _js=${3:-$LUKS2_JSON_SIZE}
	local len=${#1}
	echo -n -E "$1" > $2
	truncate -s $((_js*512)) $2
}

function kill_bin_hdr()
{
	printf "VACUUM" | _dd of=$1 bs=1 conv=notrunc
}

function erase_checksum()
{
	_dd if=/dev/zero of=$1 bs=1 seek=$(printf %d $LUKS2_BIN_HDR_CHKS_OFFSET) count=$LUKS2_BIN_HDR_CHKS_LENGTH conv=notrunc
}

function read_sha256_checksum()
{
	_dd if=$1 bs=1 skip=$(printf %d $LUKS2_BIN_HDR_CHKS_OFFSET) count=32 | xxd -c 32 -p
}

# 1 - string with checksum
function write_checksum()
{
	test $# -eq 2 || return 1
	test $((${#1}/2)) -le $LUKS2_BIN_HDR_CHKS_LENGTH || { echo "too long"; return 1; }

	echo $1 | xxd -r -p | _dd of=$2 bs=1 seek=$(printf %d $LUKS2_BIN_HDR_CHKS_OFFSET) conv=notrunc
}

function calc_sha256_checksum_file()
{
	sha256sum $1 | cut -d ' ' -f 1
}

function calc_sha256_checksum_stdin()
{
	sha256sum - | cut -d ' ' -f 1
}

# merge bin hdr with json to form metadata area
# 1:bin_hdr 2:json 3:to 4:[json size (defaults to 12KiB)]
function merge_bin_hdr_with_json()
{
	local _js=${4:-$LUKS2_JSON_SIZE}
	local _js=$((_js*512/4096))
	_dd if=$1 of=$3 bs=4096 count=1
	_dd if=$2 of=$3 bs=4096 seek=1 count=$_js
}

function _dd()
{
	dd $@ status=none
}

function write_bin_hdr_size() {
        printf '%016x' $2 | xxd -r -p -l 16 | _dd of=$1 bs=8 count=1 seek=1 conv=notrunc
}

function write_bin_hdr_offset() {
        printf '%016x' $2 | xxd -r -p -l 16 | _dd of=$1 bs=8 count=1 seek=32 conv=notrunc
}
