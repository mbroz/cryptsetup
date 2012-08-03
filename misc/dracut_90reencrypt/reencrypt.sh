#!/bin/sh
#
# $1=$device [$2=keyfile|none [$3=size]]
#

[ -d /sys/module/dm_crypt ] || modprobe dm_crypt

[ -f /tmp/reencrypted ] && exit 0

. /lib/dracut-lib.sh

# if device name is /dev/dm-X, convert to /dev/mapper/name
if [ "${1##/dev/dm-}" != "$1" ]; then
    device="/dev/mapper/$(dmsetup info -c --noheadings -o name "$1")"
else
    device="$1"
fi

PARAMS="$device -T 1 --use-fsync -B 32"
if [ -n "$3" ]; then
    PARAMS="$PARAMS --device-size $3"
fi

reenc_readkey() {
    local keypath="${1#*:}"
    local keydev="${1%%:*}"

    local mntp="/tmp/reencrypted-mount-tmp"
    mkdir "$mntp"
    mount -r "$keydev" "$mntp" && cat "$mntp/$keypath"
    umount "$mntp"
    rm -r "$mntp"
}

reenc_run() {
    local cwd=$(pwd)
    cd /tmp
    if [ "$1" = "none" ] ; then
        /bin/plymouth ask-for-password \
        --prompt "LUKS password for REENCRYPTING $device" \
        --command="/sbin/cryptsetup-reencrypt $PARAMS"
    else
        info "REENCRYPT using key $1"
        reenc_readkey "$1" | /sbin/cryptsetup-reencrypt -d - $PARAMS
    fi
    cd $cwd
}

info "REENCRYPT $device requested"
# flock against other interactive activities
{ flock -s 9;
    reenc_run $2
} 9>/.console.lock

# do not ask again
>> /tmp/reencrypted

exit 0
