fs = import('fs')

add_test_setup('default',
    is_default: true,
    exclude_suites: [ 'valgrind' ]
)

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
unit_utils_crypt_test = executable('unit-utils-crypt-test-test',
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

tests_env_valg = tests_env
tests_env_valg.set('VALG', '1')

tests_env_valg_api_00 = tests_env
tests_env_valg_api_00.set('INFOSTRING','api-test-000')

tests_env_valg_api_02 = tests_env
tests_env_valg_api_02.set('INFOSTRING','api-test-002')

tests_env_valg_unit_crypt = tests_env
tests_env_valg_unit_crypt.set('INFOSTRING','unit-utils-crypt-test')

tests_env_valg_vector = tests_env
tests_env_valg_vector.set('INFOSTRING','vector-test')

test('00modules-test',
    find_program('./00modules-test'),
    workdir: meson.current_build_dir(),
    env: tests_env,
    timeout: 14400,
    is_parallel: false,
    priority: 9999)
test('api-test',
    api_test,
    workdir: meson.current_build_dir(),
    env: tests_env,
    timeout: 14400,
    is_parallel: false)
test('valg-api-test',
    find_program('./valg-api.sh'),
    args: [ './api-test'],
    depends: [ api_test ],
    workdir: meson.current_build_dir(),
    env: tests_env_valg_api_00,
    timeout: 14400,
    is_parallel: false,
    suite: 'valgrind')
test('api-test-2',
    api_test_2,
    workdir: meson.current_build_dir(),
    env: tests_env,
    timeout: 14400,
    is_parallel: false)
test('valg-api-test-2',
    find_program('./valg-api.sh'),
    args: [ './api-test-2'],
    depends: [ api_test_2 ],
    workdir: meson.current_build_dir(),
    env: tests_env_valg_api_02,
    timeout: 14400,
    is_parallel: false,
    suite: 'valgrind')
test('blockwise-compat-test',
    find_program('./blockwise-compat-test'),
    workdir: meson.current_build_dir(),
    env: tests_env,
    timeout: 14400,
    is_parallel: false,
    depends: [
        unit_utils_io,
    ])
test('keyring-test',
    find_program('./keyring-test'),
    workdir: meson.current_build_dir(),
    env: tests_env,
    timeout: 14400,
    is_parallel: false)
test('vectors-test',
    vectors_test,
    workdir: meson.current_build_dir(),
    timeout: 14400,
    is_parallel: false)
test('unit-wipe-test',
    find_program('./unit-wipe-test'),
    workdir: meson.current_build_dir(),
    env: tests_env,
    timeout: 14400,
    is_parallel: false,
    depends: [
        unit_wipe,
    ])
test('unit-utils-crypt-test',
    unit_utils_crypt_test,
    workdir: meson.current_build_dir(),
    env: tests_env,
    timeout: 14400,
    is_parallel: false)
test('valg-unit-utils-crypt-test',
    find_program('./valg-api.sh'),
    args: [ './unit-utils-crypt-test' ],
    depends: [ unit_utils_crypt_test ],
    workdir: meson.current_build_dir(),
    env: tests_env_valg_unit_crypt,
    timeout: 14400,
    is_parallel: false,
    suite: 'valgrind')

if not enable_static
    test('run-all-symbols',
        find_program('./run-all-symbols'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            all_symbols_test,
            libcryptsetup,
        ])
endif

if get_option('cryptsetup')
    test('compat-args-test',
        find_program('./compat-args-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
            test_symbols_list_h,
        ])
    test('valg-compat-args-test',
        find_program('./compat-args-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
            test_symbols_list_h,
        ])
    test('compat-test',
        find_program('./compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
            differ,
        ])
    test('valg-compat-test',
        find_program('./compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
            differ,
        ])
    test('compat-test2',
        find_program('./compat-test2'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-compat-test2',
        find_program('./compat-test2'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('compat-test-opal',
        find_program('./compat-test-opal'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-compat-test-opal',
        find_program('./compat-test-opal'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('loopaes-test',
        find_program('./loopaes-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-loopaes-test',
        find_program('./loopaes-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('align-test',
        find_program('./align-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-align-test',
        find_program('./align-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('align-test2',
        find_program('./align-test2'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-align-test2',
        find_program('./align-test2'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('discards-test',
        find_program('./discards-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-discards-test',
        find_program('./discards-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('mode-test',
        find_program('./mode-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-mode-test',
        find_program('./mode-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('password-hash-test',
        find_program('./password-hash-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-password-hash-test',
        find_program('./password-hash-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('tcrypt-compat-test',
        find_program('./tcrypt-compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-tcrypt-compat-test',
        find_program('./tcrypt-compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('luks1-compat-test',
        find_program('./luks1-compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-luks1-compat-test',
        find_program('./luks1-compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('device-test',
        find_program('./device-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-device-test',
        find_program('./device-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('keyring-compat-test',
        find_program('./keyring-compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-keyring-compat-test',
        find_program('./keyring-compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('luks2-validation-test',
        find_program('./luks2-validation-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-luks2-validation-test',
        find_program('./luks2-validation-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('luks2-integrity-test',
        find_program('./luks2-integrity-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-luks2-integrity-test',
        find_program('./luks2-integrity-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('bitlk-compat-test',
        find_program('./bitlk-compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-bitlk-compat-test',
        find_program('./bitlk-compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('fvault2-compat-test',
        find_program('./fvault2-compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-fvault2-compat-test',
        find_program('./fvault2-compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('reencryption-compat-test',
        find_program('./reencryption-compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-reencryption-compat-test',
        find_program('./reencryption-compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('luks2-reencryption-test',
        find_program('./luks2-reencryption-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-luks2-reencryption-test',
        find_program('./luks2-reencryption-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
    test('luks2-reencryption-mangle-test',
        find_program('./luks2-reencryption-mangle-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup,
        ])
    test('valg-luks2-reencryption-mangle-test',
        find_program('./luks2-reencryption-mangle-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup,
        ])
endif

if get_option('veritysetup')
    test('verity-compat-test',
        find_program('verity-compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            veritysetup,
        ])
    test('valg-verity-compat-test',
        find_program('verity-compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            veritysetup,
        ])
endif

if get_option('integritysetup')
    test('integrity-compat-test',
        find_program('integrity-compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            integritysetup,
        ])
    test('valg-integrity-compat-test',
        find_program('integrity-compat-test'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            integritysetup,
        ])
endif

if get_option('ssh-token') and not enable_static
    test('ssh-test-plugin',
        find_program('ssh-test-plugin'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            cryptsetup_ssh,
            libcryptsetup_token_ssh,
        ])
    test('valg-ssh-test-plugin',
        find_program('ssh-test-plugin'),
        workdir: meson.current_build_dir(),
        env: tests_env_valg,
        timeout: 14400,
        is_parallel: false,
        suite: 'valgrind',
        depends: [
            cryptsetup_ssh,
            libcryptsetup_token_ssh,
        ])
endif

if get_option('external-tokens') and not enable_static
    test('systemd-test-plugin',
        find_program('systemd-test-plugin'),
        workdir: meson.current_build_dir(),
        env: tests_env,
        timeout: 14400,
        is_parallel: false,
        depends: [
            fake_systemd_tpm_path,
        ])
endif

subdir('fuzz')
