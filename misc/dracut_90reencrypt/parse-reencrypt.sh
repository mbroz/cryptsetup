#!/bin/sh

REENC=$(getargs rd.luks.reencrypt=)
# shellcheck disable=SC2086
REENC_DEV=$(echo $REENC | sed 's/:.*//')
# shellcheck disable=SC2086
REENC_SIZE=$(echo $REENC | sed -n 's/.*://p')

REENC_KEY=$(getargs rd.luks.reencrypt_key=)
if [ -z "$REENC_KEY" ] ; then
    REENC_KEY=none
fi

REENC_SLOT=$(getargs rd.luks.reencrypt_keyslot=)
if [ -z "$REENC_SLOT" ] ; then
    REENC_SLOT=any
fi

# shellcheck disable=SC2086
# shellcheck disable=SC1004
# shellcheck disable=SC2016
if [ -n "$REENC_DEV" ] ; then
{
   printf 'SUBSYSTEM!="block", GOTO="reenc_end"\n'
   printf 'ACTION!="add|change", GOTO="reenc_end"\n'
   printf 'KERNEL=="%s", ' $REENC_DEV
   printf 'ENV{ID_FS_TYPE}=="crypto_LUKS", RUN+="/sbin/initqueue \
           --unique --onetime --settled --name crypt-reencrypt-%%k \
           /sbin/reencrypt $env{DEVNAME} %s"\n' "$REENC_KEY $REENC_SLOT $REENC_SIZE"

   printf 'ENV{ID_FS_UUID}=="*%s*", ' $REENC_DEV
   printf 'ENV{ID_FS_TYPE}=="crypto_LUKS", RUN+="/sbin/initqueue \
           --unique --onetime --settled --name crypt-reencrypt-%%k \
           /sbin/reencrypt $env{DEVNAME} %s"\n' "$REENC_KEY $REENC_SLOT $REENC_SIZE"
   printf 'LABEL="reenc_end"\n'
} > /etc/udev/rules.d/69-reencryption.rules
   initqueue --unique --finished --name crypt-reencrypt-finished-${REENC_DEV} [ -e /tmp/reencrypted ]
fi
