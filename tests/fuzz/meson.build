if get_option('fuzz-targets')
    crypt2_load_fuzz = executable('crypt2_load_fuzz',
        [
            'crypt2_load_fuzz.cc',
        ],
        dependencies: [
            devmapper,
            fuzzing_engine,
        ],
        link_with: [
            libcryptsetup,
            libcrypto_backend,
            libutils_io,
        ],
        link_args: [
            link_args,
        ],
        include_directories: includes_tools)

    crypt2_load_ondisk_fuzz = executable('crypt2_load_ondisk_fuzz',
        [
            'crypt2_load_ondisk_fuzz.cc',
        ],
        dependencies: [
            devmapper,
            fuzzing_engine,
        ],
        link_with: [
            libcryptsetup,
            libcrypto_backend,
            libutils_io,
        ],
        link_args: [
            link_args,
        ],
        include_directories: includes_tools)

    crypt_load_misc_fuzz = executable('crypt_load_misc_fuzz',
        [
            'crypt_load_misc_fuzz.cc',
        ],
        dependencies: [
            devmapper,
            fuzzing_engine,
        ],
        link_with: [
            libcryptsetup,
            libcrypto_backend,
            libutils_io,
        ],
        link_args: [
            link_args,
        ],
        include_directories: includes_tools)
endif
