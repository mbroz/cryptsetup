#!/bin/bash

# all in 512 bytes blocks
# LUKS2 with 16KiB header
LUKS2_HDR_SIZE=32 # 16 KiB
LUKS2_BIN_HDR_SIZE=8 # 4096 B
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

function read_luks2_bin_hdr0()
{
	_dd if=$1 of=$2 bs=512 count=$LUKS2_BIN_HDR_SIZE
}

function read_luks2_json0()
{
	_dd if=$1 of=$2 bs=512 skip=$LUKS2_BIN_HDR_SIZE count=$LUKS2_JSON_SIZE
}

function read_luks2_bin_hdr1()
{
	_dd if=$1 of=$2 skip=$LUKS2_HDR_SIZE bs=512 count=$LUKS2_BIN_HDR_SIZE
}

function read_luks2_json1()
{
	_dd if=$1 of=$2 bs=512 skip=$((LUKS2_BIN_HDR_SIZE+LUKS2_HDR_SIZE)) count=$LUKS2_JSON_SIZE
}

function read_luks2_hdr_area0()
{
	_dd if=$1 of=$2 bs=512 count=$LUKS2_HDR_SIZE
}

function read_luks2_hdr_area1()
{
	_dd if=$1 of=$2 bs=512 skip=$LUKS2_HDR_SIZE count=$LUKS2_HDR_SIZE
}

function write_luks2_bin_hdr1()
{
	_dd if=$1 of=$2 bs=512 seek=$LUKS2_HDR_SIZE count=$LUKS2_BIN_HDR_SIZE conv=notrunc
}

function write_luks2_hdr0()
{
	_dd if=$1 of=$2 bs=512 count=$LUKS2_HDR_SIZE conv=notrunc
}

function write_luks2_hdr1()
{
	_dd if=$1 of=$2 bs=512 seek=$LUKS2_HDR_SIZE count=$LUKS2_HDR_SIZE conv=notrunc
}

# 1 - json str
function write_luks2_json()
{
	local len=${#1}
	printf '%s' "$1" | _dd of=$2 bs=1 count=$len conv=notrunc
	_dd if=/dev/zero of=$2 bs=1 seek=$len count=$((LUKS2_JSON_SIZE*512-len))
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

# 1 - bin
# 2 - json
# 3 - luks2_hdr_area
function merge_bin_hdr_with_json()
{
	_dd if=$1 of=$3 bs=512 count=$LUKS2_BIN_HDR_SIZE
	_dd if=$2 of=$3 bs=512 seek=$LUKS2_BIN_HDR_SIZE count=$LUKS2_JSON_SIZE
}

function _dd()
{
	dd $@ 2>/dev/null
	#dd $@
}
