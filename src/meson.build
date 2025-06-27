src_build_dir = meson.current_build_dir()

if get_option('cryptsetup')
    cryptsetup_files = files(
        'cryptsetup.c',
        'utils_args.c',
        'utils_blockdev.c',
        'utils_luks.c',
        'utils_password.c',
        'utils_progress.c',
        'utils_reencrypt.c',
        'utils_reencrypt_luks1.c',
        'utils_tools.c',
        'utils_key_description.c',
        'utils_keyslot_check.c',
    )
    cryptsetup_files += lib_tools_files
    cryptsetup_deps = [
        popt,
        pwquality,
        passwdqc,
        uuid,
        blkid,
    ]
    cryptsetup = executable('cryptsetup',
        cryptsetup_files,
        dependencies: cryptsetup_deps,
        install: true,
        install_dir: get_option('sbindir'),
        link_with: libcryptsetup,
        link_args: link_args,
        include_directories: includes_tools)
endif

if get_option('veritysetup')
    veritysetup_files = files(
        'utils_args.c',
        'utils_tools.c',
        'veritysetup.c',
    )
    veritysetup_files += lib_tools_files
    veritysetup_deps = [
        popt,
        blkid,
    ]

    veritysetup = executable('veritysetup',
        veritysetup_files,
        dependencies: veritysetup_deps,
        install: true,
        install_dir: get_option('sbindir'),
        link_with: libcryptsetup,
        link_args: link_args,
        include_directories: includes_tools)
endif

if get_option('integritysetup')
    integritysetup_files = files(
        'integritysetup.c',
        'utils_args.c',
        'utils_blockdev.c',
        'utils_progress.c',
        'utils_tools.c',
    )
    integritysetup_files += lib_tools_files
    integritysetup_deps = [
        popt,
        uuid,
        blkid,
    ]

    integritysetup = executable('integritysetup',
        integritysetup_files,
        dependencies: integritysetup_deps,
        install: true,
        install_dir: get_option('sbindir'),
        link_with: libcryptsetup,
        link_args: link_args,
        include_directories: includes_tools)
endif

src_ssh_token_files = files(
    'utils_password.c',
    'utils_tools.c',
)
