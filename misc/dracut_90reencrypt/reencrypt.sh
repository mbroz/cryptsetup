#!/bin/sh
#
# $1=$device [$2=keyfile|none [$3=keyslot|any [$4=size]]]
#

[ -d /sys/module/dm_crypt ] || modprobe dm_crypt

[ -d /sys/module/loop ] || modprobe loop

[ -f /tmp/reencrypted ] && exit 0

. /lib/dracut-lib.sh

# if device name is /dev/dm-X, convert to /dev/mapper/name
if [ "${1##/dev/dm-}" != "$1" ]; then
    device="/dev/mapper/$(dmsetup info -c --noheadings -o name "$1")"
else
    device="$1"
fi

PARAMS="$device -T 1 --use-fsync --progress-frequency 5 -B 32"
if [ "$3" != "any" ]; then
    PARAMS="$PARAMS -S $3"
fi

if [ -n "$4" ]; then
    PARAMS="$PARAMS --device-size $4"
fi

reenc_readkey() {
    keypath="${1#*:}"
    keydev="${1%%:*}"

    mntp="/tmp/reencrypted-mount-tmp"
    mkdir "$mntp"
    mount -r "$keydev" "$mntp" && cat "$mntp/$keypath"
    umount "$mntp"
    rm -r "$mntp"
}

# shellcheck disable=SC2086
# shellcheck disable=SC2164
reenc_run() {
    cwd=$(pwd)
    _prompt="LUKS password for REENCRYPTING $device"
    cd /tmp
    udevadm settle
    if [ "$1" = "none" ] ; then
	if [ "$2" != "any" ]; then
		_prompt="$_prompt, using keyslot $2"
	fi
        /bin/plymouth ask-for-password \
        --prompt "$_prompt" \
        --command="/sbin/cryptsetup-reencrypt-verbose $PARAMS"
    else
        info "REENCRYPT using key $1"
        reenc_readkey "$1" | /sbin/cryptsetup-reencrypt-verbose -d - $PARAMS
    fi
    _ret=$?
    cd $cwd
}

info "REENCRYPT $device requested"
# flock against other interactive activities
# shellcheck disable=SC2086
{ flock -s 9;
    reenc_run $2 $3
} 9>/.console_lock

if [ $_ret -eq 0 ]; then
    # do not ask again
    # shellcheck disable=SC2188
    >> /tmp/reencrypted
    warn "Reencryption of device $device has finished successfully. Use previous"
    warn "initramfs image (without reencrypt module) to boot the system. When"
    warn "you leave the emergency shell, the system will reboot."

    emergency_shell -n "(reboot)"
    [ -x /usr/bin/systemctl ] && /usr/bin/systemctl reboot
    [ -x /sbin/shutdown ] && /sbin/shutdown -r now
fi

# panic the kernel otherwise
exit 1
