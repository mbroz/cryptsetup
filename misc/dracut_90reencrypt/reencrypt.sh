#!/bin/sh

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
if [ -n "$2" ]; then
    PARAMS="$PARAMS --device-size $2"
fi

info "REENCRYPT $device requested"
# flock against other interactive activities
{ flock -s 9;
    CURR=$(pwd)
    cd /tmp
    /bin/plymouth ask-for-password --prompt "LUKS password for REENCRYPTING $device" \
      --command="/sbin/cryptsetup-reencrypt $PARAMS"
    cd $CURR
} 9>/.console.lock

# do not ask again
>> /tmp/reencrypted

exit 0
