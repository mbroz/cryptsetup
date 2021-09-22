#!/bin/bash

#Author: JT Moree
#License: Same as cryptsetup

# use gpg to decrypt passphrase or key and open LUKS container

function cleanup() {
    if [ -d "$LUKS_TEMP" ] ; then
        rm -rf "$LUKS_TEMP"
    fi
}

function die() {
    cleanup
    echo "$2" >&2
    exit $1
}

function setup-sudo() {
    if [ "$UID" = 0 ] ; then
        echo "running as root"
    elif [ -n "$LUKS_FORCE_SUDO" ] ; then
        echo "running as non root. do we need to force SUDO on everything"
        FSUDO="sudo"
    else
        echo "running as non root which will require no locking and user will need to have access to block devices."
        SUDO="sudo"
        LOCKS="--disable-locks"
    fi
}

function get-token() {
    get_token_dev=$1
    get_token_id=$2
    get_token_file=$3

    $SUDO cryptsetup token export $get_token_dev --token-id $get_token_id $LOCKS > $get_token_file
    if [ ! -f "$get_token_file" ] || [ -z "`cat $get_token_file`" ] ; then
        die 101 "Error!  Could not extract json token data"
    fi
}

function check_token() {
    check_tokenkey_file=$1

    check_tokenkey_type=`cat $check_tokenkey_file | jq .type | tr -d '"'`
    if [ "$check_tokenkey_type" != "smartcard" ] ; then
        die 110 "Error!   Token type must be 'smartcard'"
    fi
    check_tokenkey_subtype=`cat $check_tokenkey_file | jq .subtype | tr -d '"'`
    if [ "`cat $check_tokenkey_file | jq .key | tr -d '"'`" = "" ] ; then
        die 112 "Error!  Token key is empty"
    fi
    echo $check_tokenkey_subtype
}

function extract-tokenkey() {
    extract_tokenkey_json=$1
    extract_tokenkey_gpg=$2

    extract_tokenkey_data=`cat $extract_tokenkey_json | jq .key | tr -d '"'`
    N=$'\n'
    echo -e "${extract_tokenkey_data}" > $extract_tokenkey_gpg
    if [ -z "`cat $extract_tokenkey_gpg`" ] ; then
        die 112 "Error!  Failed to extract Token key"
    fi
}

function validate-device() {
    if [ -z "$LUKS_DEV" ] ; then
        die 21 "Error!  No device specified"
    fi
    $SUDO cryptsetup isLuks $LUKS_DEV --disable-locks
    if [ "$?" != "0" ] ; then
        die 20 "Error!  $1 is not a valid LUKS container"
    fi
}

function check-open() {
    check_open_dev=$1
    # is luks device already in use ?
    $SUDO cryptsetup isLuks $check_open_dev $LOCKS >/dev/null 2>/dev/null
    check_open_s=$?
    if [ "$check_open_s" = "0" ] ; then
        check_open_uuid=$( $SUDO cryptsetup luksUUID $check_open_dev | tr -d -)
        if [ -b /dev/disk/by-id/dm-uuid-*$check_open_uuid* ] ; then
            die 667 "Error!  '$check_open_dev' is already opened."
        fi
    fi
}

function validate-inputs() {
    validate-device
    check-open "$LUKS_DEV"
    if [ -z "$TOKENID" ] ; then
        die 25 "Error!  No token id specified"
    fi
}

function usage() {
    cat << EOF
This script is a reference implementation for using LUKS with smartcards.  It decrypts a LUKS container using a smartcard. 

Usage:  $ME <device> <token id> [OPTIONS]

    The device must be a valid LUKS2 device.

    The token id is the integer corresponding to the token in the LUKS2 header that holds the gpg encrypted secret.

    -D : debug

    -m <mem>: pass to cryptsetup --pbkdf-memory

    -n <name> : name of open device in /dev/mapper

    -t : test mode.  any open container will be closed before exit

EOF
}

if [ "$1" = "-h" ] ; then
    usage
    exit 1
fi

LUKS_DEV=$1
shift
TOKENID=$1
shift

SUDO=
FSUDO=
LOCKS=
ENC_TYPE='gpg'

while getopts "hDm:n:t" opt ; do
    case "$opt" in
        h)  usage
            exit 1
            ;;
        D)  LUKS_DEBUG=" --debug "
            ;;
        m)  LUKS_MEM=" --pbkdf-memory ${OPTARG} "
            ;;
        n)  LUKS_NAME=${OPTARG}
            ;;
        t)  LUKS_TEST="yes"
    esac
done

#CHECK FOR DEPENDENCIES
if [ -z "`which jq`" ] ; then
    die 100 "Missing jq dependency.  Needed for json"
fi

setup-sudo
validate-inputs
LUKS_UUID=`$SUDO cryptsetup luksUUID $LUKS_DEV $LOCKS`
LUKS_NAME=${LUKS_NAME:-luks-${LUKS_UUID}}
LUKS_TEMP=`mktemp -d`
JSON_FILE=$LUKS_TEMP/json
GPG_FILE=$LUKS_TEMP/key.asc

echo "Using temp location $LUKS_TEMP"
get-token $LUKS_DEV $TOKENID $JSON_FILE
SUBTYPE=`check_token $JSON_FILE`
extract-tokenkey $JSON_FILE $GPG_FILE
if [ "$SUBTYPE" = "gpg" ] ; then
    echo "gpg --decrypt ${GPG_FILE} | $FSUDO $SUDO cryptsetup luksOpen $LUKS_DEV $LUKS_NAME --key-file=- $LUKS_DEBUG $LUKS_MEM"
    gpg --decrypt "${GPG_FILE}" | $FSUDO $SUDO cryptsetup luksOpen $LUKS_DEV $LUKS_NAME --key-file=- $LUKS_DEBUG $LUKS_MEM
else
    die 666 "invalid token subtype found '$SUBTYPE'"
fi
if [ "$?" = "0" ] ; then
    MAPPER=/dev/mapper/$LUKS_NAME
    if [ -b "$MAPPER" ] ; then
        echo "LUKS2 container opened at $MAPPER"
        if [ "$LUKS_TEST" = "yes" ] ; then
            $FSUDO $SUDO cryptsetup luksClose $MAPPER $LOCKS
        fi
    else
        die 200 "Error!  Could not access opened LUKS container at $MAPPER"
    fi
else
    exit $?
fi
