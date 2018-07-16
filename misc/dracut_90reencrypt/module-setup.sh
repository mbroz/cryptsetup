#!/bin/bash

check() {
    [ -x /sbin/cryptsetup-reencrypt ] || return 1
    return 255
}

depends() {
    echo dm rootfs-block
}

installkernel() {
    # requires hostonly='' override so that loop module is pulled in initramfs
    # even if not loaded in actual kernel. dracut bug?
    hostonly='' instmods dm_crypt =crypto loop
}

install() {
    if dracut_module_included crypt; then
        derror "'reencrypt' can't be installed together with 'crypt'."
        derror "Add '-o crypt' option to install reencrypt module."
        return 1
    fi

    dracut_install cryptsetup-reencrypt

    # moddir variable is assigned in dracut general shell lib
    # shellcheck disable=SC2154
    inst_hook cmdline 30 "$moddir/parse-reencrypt.sh"
    inst_simple "$moddir"/reencrypt.sh /sbin/reencrypt
    inst_simple "$moddir"/reencrypt-verbose.sh /sbin/cryptsetup-reencrypt-verbose
}
