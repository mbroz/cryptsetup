tokens_ssh_build_dir = meson.current_build_dir()

if get_option('ssh-token')
    if not enable_static
        libcryptsetup_token_ssh = shared_library(
            'cryptsetup-token-ssh',
            [
                'libcryptsetup-token-ssh.c',
                'ssh-utils.c',
            ],
            dependencies: [
                jsonc,
                libssh,
            ],
            link_with: libcryptsetup,
            link_args: token_link_args,
            include_directories: includes_tools + ['..'])
    endif

    cryptsetup_ssh_files = files(
        'cryptsetup-ssh.c',
        'ssh-utils.c',
    )
    cryptsetup_ssh_files += lib_ssh_token_files
    cryptsetup_ssh_files += src_ssh_token_files

    cryptsetup_ssh = executable('cryptsetup-ssh',
        cryptsetup_ssh_files,
        dependencies: [
            argp,
            jsonc,
            libssh,
            passwdqc,
            popt,
            pwquality,
        ],
        link_with: libcryptsetup,
        include_directories: includes_tools + ['..'])
endif
