#!/bin/sh

REENC=$(getargs rd_REENCRYPT=)
REENC_DEV=$(echo $REENC | sed 's/:.*//')
REENC_SIZE=$(echo $REENC | sed -n 's/.*://p')

REENC_KEY=$(getargs rd_REENCRYPT_KEY=)
if [ -z "$REENC_KEY" ] ; then
    REENC_KEY=none
fi

if [ -n "$REENC_DEV" ] ; then
{
   printf 'SUBSYSTEM!="block", GOTO="reenc_end"\n'
   printf 'ACTION!="add|change", GOTO="reenc_end"\n'
   printf 'KERNEL!="%s", GOTO="reenc_end"\n' $REENC_DEV
   printf 'ENV{ID_FS_TYPE}=="crypto_LUKS", RUN+="/sbin/initqueue \
           --unique --onetime --name crypt-reencrypt-%%k \
           /sbin/reencrypt $env{DEVNAME} %s"\n' "$REENC_KEY $REENC_SIZE"
   printf 'LABEL="reenc_end"\n'
} > /etc/udev/rules.d/69-reencryption.rules
fi
