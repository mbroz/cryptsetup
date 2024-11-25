fs = import('fs')

# copy images and generators to build directory from where tests run
test_files_to_copy = [
    'bitlk-images.tar.xz',
    'blkid-luks2-pv.img.xz',
    'compatimage.img.xz',
    'compatimage2.img.xz',
    'compatv10image.img.xz',
    'conversion_imgs.tar.xz',
    'evil_hdr-keyslot_overlap.xz',
    'evil_hdr-luks_hdr_damage.xz',
    'evil_hdr-payload_overwrite.xz',
    'evil_hdr-small_luks_device.xz',
    'evil_hdr-stripes_payload_dmg.xz',
    'fvault2-images.tar.xz',
    'generators/generate-luks2-area-in-json-hdr-space-json0.img.sh',
    'img_fs_ext4.img.xz',
    'img_fs_vfat.img.xz',
    'img_fs_xfs.img.xz',
    'img_fs_xfs5.img.xz',
    'luks1-images.tar.xz',
    'luks2_header_requirements.tar.xz',
    'luks2_keyslot_unassigned.img.xz',
    'luks2_mda_images.tar.xz',
    'luks2_valid_hdr.img.xz',
    'luks2_invalid_cipher.img.xz',
    'tcrypt-images.tar.xz',
    'valid_header_file.xz',
    'xfs_512_block_size.img.xz',
    'valg.sh',
    'cryptsetup-valg-supps',
    'LUKS-d238e48a-0ed3-4169-b841-f26b44693134.tar.xz'
]

foreach file : test_files_to_copy
    fs.copyfile(file)
endforeach

api_test = executable('api-test',
    [
        'api-test.c',
        'test_utils.c',
    ],
    dependencies: devmapper,
    link_with: libcryptsetup,
    c_args: ['-DNO_CRYPTSETUP_PATH'],
    include_directories: includes_lib)

api_test_2 = executable('api-test-2',
    [
        'api-test-2.c',
        'test_utils.c',
    ],
    dependencies: devmapper,
    link_with: libcryptsetup,
    c_args: [
        '-DNO_CRYPTSETUP_PATH',
    ],
    include_directories: includes_lib)

crypto_check = executable('crypto-check',
    [
        'crypto-check.c',
    ],
    link_with: libcrypto_backend,
    c_args: [
        '-Wall',
        '-O2',
    ],
    include_directories: includes_lib)

vectors_test = executable('vectors-test',
    [
        'crypto-vectors.c',
    ],
    link_with: libcrypto_backend,
    c_args: [
        '-DNO_CRYPTSETUP_PATH',
    ],
    include_directories: includes_lib)

differ = executable('differ',
    [
        'differ.c',
    ],
    c_args: [
        '-Wall',
        '-O2',
    ])

unit_utils_io = executable('unit-utils-io',
    [
        'unit-utils-io.c',
    ],
    link_with: libutils_io,
    c_args: [
        '-DNO_CRYPTSETUP_PATH',
    ],
    include_directories: includes_lib)

unit_utils_crypt_test = files('unit-utils-crypt.c',) + lib_utils_crypt_files
unit_utils_crypt_test = executable('unit-utils-crypt-test',
    unit_utils_crypt_test,
    link_with: libcryptsetup,
    c_args: [
        '-DNO_CRYPTSETUP_PATH',
    ],
    include_directories: includes_lib)

unit_wipe = executable('unit-wipe',
    [
        'unit-wipe.c',
    ],
    link_with: libcryptsetup,
    c_args: [
        '-DNO_CRYPTSETUP_PATH',
    ],
    include_directories: includes_lib)

generate_symbols_list = find_program('generate-symbols-list')
test_symbols_list_h = custom_target('test-symbols-list.h',
    output: 'test-symbols-list.h',
    input: [
        libcryptsetup_sym_path,
    ],
    # the scripts writes the output to stdout, capture and write to output file
    capture: true,
    command: [
        generate_symbols_list,
        '@INPUT@',
    ])
all_symbols_test = executable('all-symbols-test',
    [
        'all-symbols-test.c',
        test_symbols_list_h,
    ],
    dependencies: dl,
    link_with: libcryptsetup,
    c_args: [
        '-DNO_CRYPTSETUP_PATH',
    ],
    include_directories: includes_lib)

fake_systemd_tpm_path = shared_library('fake_systemd_tpm_path',
    [
        'fake_systemd_tpm_path.c',
    ],
    name_prefix: '',
    build_by_default: not enable_static)

tests_env = environment()
tests_env.set('CRYPTSETUP_PATH', src_build_dir)
tests_env.set('LIBCRYPTSETUP_DIR', lib_build_dir)
tests_env.set('srcdir', meson.current_source_dir())
tests_env.set('SSH_BUILD_DIR', tokens_ssh_build_dir)
tests_env.set('CRYPTSETUP_TESTS_RUN_IN_MESON', '1')

valgrind_tests_env = tests_env
valgrind_tests_env.set('VALG', '1')

add_test_setup('default',
    is_default: true,
    env: tests_env,
    exclude_suites: [ 'valgrind-only' ]
)

add_test_setup('valgrind',
    env: valgrind_tests_env,
    exclude_suites: [ 'not-in-valgrind' ]
)

test('00modules-test',
    find_program('./00modules-test'),
    workdir: meson.current_build_dir(),
    timeout: 14400,
    is_parallel: false,
    suite: 'not-in-valgrind',
    priority: 9999)
test('api-test',
    api_test,
    workdir: meson.current_build_dir(),
    timeout: 14400,
    is_parallel: false,
    suite: 'not-in-valgrind')
test('valg-api-test',
    find_program('./valg-api.sh'),
    args: [ './api-test'],
    depends: [ api_test ],
    workdir: meson.current_build_dir(),
    env: 'INFOSTRING=api-test-000',
    timeout: 14400,
    is_parallel: false,
    suite: 'valgrind-only')
test('api-test-2',
    api_test_2,
    workdir: meson.current_build_dir(),
    timeout: 14400,
    is_parallel: false,
    suite: 'not-in-valgrind')
test('valg-api-test-2',
    find_program('./valg-api.sh'),
    args: [ './api-test-2'],
    depends: [ api_test_2 ],
    workdir: meson.current_build_dir(),
    env: 'INFOSTRING=api-test-002',
    timeout: 14400,
    is_parallel: false,
    suite: 'valgrind-only')
test('blockwise-compat-test',
    find_program('./blockwise-compat-test'),
    workdir: meson.current_build_dir(),
    timeout: 14400,
    is_parallel: false,
    suite: 'not-in-valgrind',
    depends: [
        unit_utils_io,
    ])
test('keyring-test',
    find_program('./keyring-test'),
    workdir: meson.current_build_dir(),
    timeout: 14400,
    is_parallel: false,
    suite: 'not-in-valgrind')
test('vectors-test',
    vectors_test,
    workdir: meson.current_build_dir(),
    timeout: 14400,
    is_parallel: false,
    suite: 'not-in-valgrind')
test('valg-vectors-test',
    find_program('./valg-api.sh'),
    args: [ './vectors-test' ],
    depends: [ vectors_test ],
    workdir: meson.current_build_dir(),
    env: 'INFOSTRING=vectors-test',
    timeout: 14400,
    is_parallel: false,
    suite: 'valgrind-only')
test('unit-wipe-test',
    find_program('./unit-wipe-test'),
    workdir: meson.current_build_dir(),
    timeout: 14400,
    is_parallel: false,
    suite: 'not-in-valgrind',
    depends: [
        unit_wipe,
    ])
test('unit-utils-crypt-test',
    unit_utils_crypt_test,
    workdir: meson.current_build_dir(),
    timeout: 14400,
    is_parallel: false,
    suite: 'not-in-valgrind')
test('valg-unit-utils-crypt-test',
    find_program('./valg-api.sh'),
    args: [ './unit-utils-crypt-test' ],
    depends: [ unit_utils_crypt_test ],
    workdir: meson.current_build_dir(),
    env: 'INFOSTRING=unit-utils-crypt-test',
    timeout: 14400,
    is_parallel: false,
    suite: 'valgrind-only')

if not enable_static
    test('run-all-symbols',
        find_program('./run-all-symbols'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        suite: 'not-in-valgrind',
        depends: [
            all_symbols_test,
            libcryptsetup,
        ])
endif

if get_option('cryptsetup')
    test('compat-args-test',
        find_program('./compat-args-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
            test_symbols_list_h,
        ])
    test('compat-test',
        find_program('./compat-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
            differ,
        ])
    test('compat-test2',
        find_program('./compat-test2'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('compat-test-opal',
        find_program('./compat-test-opal'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('loopaes-test',
        find_program('./loopaes-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('align-test',
        find_program('./align-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('align-test2',
        find_program('./align-test2'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('discards-test',
        find_program('./discards-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('mode-test',
        find_program('./mode-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('password-hash-test',
        find_program('./password-hash-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('tcrypt-compat-test',
        find_program('./tcrypt-compat-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
            crypto_check,
        ])
    test('luks1-compat-test',
        find_program('./luks1-compat-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
            crypto_check,
        ])
    test('device-test',
        find_program('./device-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('keyring-compat-test',
        find_program('./keyring-compat-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('keyring-trusted-test',
        find_program('./keyring-trusted-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('luks2-validation-test',
        find_program('./luks2-validation-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('luks2-integrity-test',
        find_program('./luks2-integrity-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('bitlk-compat-test',
        find_program('./bitlk-compat-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('fvault2-compat-test',
        find_program('./fvault2-compat-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('reencryption-compat-test',
        find_program('./reencryption-compat-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('luks2-reencryption-test',
        find_program('./luks2-reencryption-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('luks2-reencryption-mangle-test',
        find_program('./luks2-reencryption-mangle-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
endif

if get_option('veritysetup')
    test('verity-compat-test',
        find_program('verity-compat-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            veritysetup,
        ])
endif

if get_option('integritysetup')
    test('integrity-compat-test',
        find_program('integrity-compat-test'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            integritysetup,
        ])
endif

if get_option('ssh-token') and not enable_static
    test('ssh-test-plugin',
        find_program('ssh-test-plugin'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup_ssh,
            libcryptsetup_token_ssh,
        ])
endif

if get_option('external-tokens') and get_option('systemd-tokens-test') and not enable_static
    test('systemd-test-plugin',
        find_program('systemd-test-plugin'),
        workdir: meson.current_build_dir(),
        timeout: 14400,
        is_parallel: false,
        suite: 'not-in-valgrind',
        depends: [
            fake_systemd_tpm_path,
        ])
endif

subdir('fuzz')
