if use_internal_argon2
    subdir('argon2')
endif

libcrypto_backend_dependencies = [
    crypto_backend_library,
    clock_gettime,
]
libcrypto_backend_link_with = []

libcrypto_backend_sources = files(
    'argon2_generic.c',
    'base64.c',
    'memutils.c',
    'cipher_check.c',
    'cipher_generic.c',
    'crc32.c',
    'crypto_cipher_kernel.c',
    'crypto_storage.c',
    'pbkdf_check.c',
    'utf8.c',
)

crypto_backend = get_option('crypto-backend')
libcrypto_backend_sources += files('crypto_@0@.c'.format(crypto_backend))

if use_internal_pbkdf2
    libcrypto_backend_sources += files('pbkdf2_generic.c')
endif

if use_internal_argon2 and get_option('argon-implementation') == 'internal'
    libcrypto_backend_link_with += libargon2
elif get_option('argon-implementation') == 'libargon2'
    libcrypto_backend_dependencies += libargon2_external
endif

libcrypto_backend = static_library('crypto_backend',
    libcrypto_backend_sources,
    include_directories: includes_lib,
    dependencies: libcrypto_backend_dependencies,
    link_with: libcrypto_backend_link_with)
