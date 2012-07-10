#!/bin/bash

check() {
    [ -x /sbin/cryptsetup-reencrypt ] || return 1
    return 255
}

depends() {
    echo dm rootfs-block
    return 0
}

installkernel() {
    instmods dm_crypt =crypto
}

install() {
    dracut_install cryptsetup-reencrypt

    inst_hook cmdline 30 "$moddir/parse-reencrypt.sh"
    inst_simple "$moddir"/reencrypt.sh /sbin/reencrypt
}