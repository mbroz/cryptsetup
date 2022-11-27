subdir('crypto_backend')
lib_build_dir = meson.current_build_dir()

libutils_io = static_library('utils_io',
    files(
        'utils_io.c',
    ))

libcryptsetup_sym_path = join_paths(meson.current_source_dir(), 'libcryptsetup.sym')

libcryptsetup_deps = [
    uuid,
    devmapper,
    libargon2_external,
    jsonc,
    blkid,
    dl,
]

libcryptsetup_sources = files(
    'bitlk/bitlk.c',
    'fvault2/fvault2.c',
    'integrity/integrity.c',
    'loopaes/loopaes.c',
    'luks1/af.c',
    'luks1/keyencryption.c',
    'luks1/keymanage.c',
    'luks2/hw_opal/hw_opal.c',
    'luks2/luks2_digest.c',
    'luks2/luks2_digest_pbkdf2.c',
    'luks2/luks2_disk_metadata.c',
    'luks2/luks2_json_format.c',
    'luks2/luks2_json_metadata.c',
    'luks2/luks2_keyslot.c',
    'luks2/luks2_keyslot_luks2.c',
    'luks2/luks2_keyslot_reenc.c',
    'luks2/luks2_luks1_convert.c',
    'luks2/luks2_reencrypt.c',
    'luks2/luks2_reencrypt_digest.c',
    'luks2/luks2_segment.c',
    'luks2/luks2_token.c',
    'luks2/luks2_token_keyring.c',
    'tcrypt/tcrypt.c',
    'verity/rs_decode_char.c',
    'verity/rs_encode_char.c',
    'verity/verity.c',
    'verity/verity_fec.c',
    'verity/verity_hash.c',
    'crypt_plain.c',
    'keyslot_context.c',
    'libdevmapper.c',
    'random.c',
    'setup.c',
    'utils.c',
    'utils_benchmark.c',
    'utils_blkid.c',
    'utils_crypt.c',
    'utils_device.c',
    'utils_device_locking.c',
    'utils_devpath.c',
    'utils_keyring.c',
    'utils_loop.c',
    'utils_pbkdf.c',
    'utils_safe_memory.c',
    'utils_storage_wrappers.c',
    'utils_wipe.c',
    'volumekey.c',
)

if enable_static
    libcryptsetup = static_library('cryptsetup',
        libcryptsetup_sources,
        dependencies: libcryptsetup_deps,
        link_with: [
            libcrypto_backend,
            libutils_io,
        ],
        install: true)
else
    libcryptsetup = library('cryptsetup',
        libcryptsetup_sources,
        dependencies: libcryptsetup_deps,
        version: libcryptsetup_version,
        link_args: [
            '-Wl,--version-script=' +
            libcryptsetup_sym_path,
        ],
        link_with: [
            libcrypto_backend,
            libutils_io,
        ],
        install: true)
endif

lib_tools_files = files(
    'utils_blkid.c',
    'utils_crypt.c',
    'utils_io.c',
    'utils_loop.c',
)
lib_utils_crypt_files = files(
    'utils_crypt.c',
)
lib_ssh_token_files = files(
    'utils_io.c',
    'utils_loop.c',
)

install_headers(
    'libcryptsetup.h',
)
pkgconfig.generate(
    libcryptsetup,
    name: 'libcryptsetup',
    version: PACKAGE_VERSION,
    description: 'cryptsetup library')
