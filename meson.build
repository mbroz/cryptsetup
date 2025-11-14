project('cryptsetup',
    'c',
    default_options: [ 'prefix=/usr' ],
    meson_version: '>=0.64',
    version: '2.9.0-git')

libcryptsetup_version = '12.11.0'

includes_root = include_directories('.')
includes_lib = include_directories('lib')
includes_tools = [
    includes_root,
    includes_lib,
]

warning('meson build system support for cryptsetup is considered experimental at the moment ')

pkgconfig = import('pkgconfig')
cc = meson.get_compiler('c')
nop_command = find_program('echo')
conf = configuration_data()

PACKAGE_VERSION = meson.project_version()
conf.set_quoted('PACKAGE_VERSION', PACKAGE_VERSION)
conf.set_quoted('PACKAGE_NAME', meson.project_name())
conf.set_quoted('PACKAGE', meson.project_name())
conf.set('_GNU_SOURCE', true)

default_string_options = [
    'default-loopaes-cipher',
    'default-luks1-cipher',
    'default-luks1-hash',
    'default-luks1-mode',
    'default-luks2-keyslot-cipher',
    'default-luks2-lock-path',
    'default-luks2-pbkdf',
    'default-plain-cipher',
    'default-plain-hash',
    'default-plain-mode',
    'default-verity-hash',
]

default_int_options = [
    'default-integrity-keyfile-size-maxkb',
    'default-keyfile-size-maxkb',
    'default-loopaes-keybits',
    'default-luks1-iter-time',
    'default-luks1-keybits',
    'default-luks2-iter-time',
    'default-luks2-keyslot-keybits',
    'default-luks2-lock-dir-perms',
    'default-luks2-memory-kb',
    'default-luks2-parallel-threads',
    'default-passphrase-size-max',
    'default-plain-keybits',
    'default-verity-data-block',
    'default-verity-fec-roots',
    'default-verity-hash-block',
    'default-verity-salt-size',
]

foreach default_option : (default_string_options)
    conf.set_quoted(default_option.underscorify().to_upper(), get_option(default_option))
endforeach

foreach default_option : (default_int_options)
    conf.set(default_option.underscorify().to_upper(), get_option(default_option))
endforeach

sanitizer = get_option('b_sanitize')
sanitizer_enabled = sanitizer != '' and sanitizer != 'none'

enable_static = get_option('enable-static')
if get_option('static-cryptsetup')
    if not enable_static
        warning('Requested static cryptsetup build, enabling static library.')
        enable_static = true
    endif

    conf.set10('STATIC_TOOLS', true)
endif
link_args = []
if enable_static == true
    if not sanitizer_enabled
        link_args += '--static'
    else
        warning('Turning off statically linked binaries as they are not compatible with sanitizer build. Will keep preferring static external dependencies.')
    endif
endif

required_headers = [
    'byteswap.h',
    'ctype.h',
    'endian.h',
    'fcntl.h',
    'inttypes.h',
    'locale.h',
    'malloc.h',
    'stdint.h',
    'sys/endian.h',
    'sys/ioctl.h',
    'sys/mman.h',
    'sys/statvfs.h',
    'sys/sysmacros.h',
    'uchar.h',
    'unistd.h',
]
foreach header : required_headers
    conf.set10('HAVE_' + header.underscorify().to_upper(), cc.has_header(header))
endforeach

fcntl_header = conf.get('HAVE_FCNTL_H') == 1 ? 'fcntl.h' : 'stdio.h'
if cc.has_header_symbol(fcntl_header, 'O_CLOEXEC')
    conf.set10('HAVE_DECL_O_CLOEXEC', true)
else
    message('O_CLOEXEC not provided, setting to 0')
    conf.set10('O_CLOEXEC', false,
        description: 'Defined to 0 if not provided')
endif

# ==========================================================================
# AsciiDoc manual pages

asciidoc = find_program('asciidoctor', required: false)
opt_asciidoc = get_option('asciidoc')
if opt_asciidoc.enabled() and not asciidoc.found()
    error('Building man pages requires asciidoctor installed.')
endif
use_asciidoc = asciidoc.found() and not opt_asciidoc.disabled()

# ==========================================================================
# keyring

if get_option('keyring')
    assert(cc.has_header('linux/keyctl.h'),
        'You need Linux kernel headers with kernel keyring service compiled.')
    assert(cc.has_header_symbol('syscall.h', '__NR_add_key',),
        'The kernel is missing add_key syscall.')
    assert(cc.has_header_symbol('syscall.h', '__NR_keyctl'),
        'The kernel is missing keyctl syscall.')
    assert(cc.has_header_symbol('syscall.h', '__NR_request_key',),
        'The kernel is missing request_key syscall.')
    conf.set10('KERNEL_KEYRING', true,
        description: 'Enable kernel keyring service support')
endif

if build_machine.endian() == 'big'
    conf.set10('WORDS_BIGENDIAN', true)
endif

# ==========================================================================

uuid = dependency('uuid',
    static: enable_static)
assert(cc.has_function('uuid_clear',
        prefix: '#include <uuid.h>', dependencies: uuid),
    'You need the uuid library.')

# ==========================================================================

# AC_SEARCH_LIBS([clock_gettime],[rt posix4])

clock_gettime = []
if not cc.has_function('clock_gettime',
        prefix: '#include <time.h>')
    clock_gettime = cc.find_library('rt')

    if not cc.has_function('clock_gettime',
            prefix: '#include <time.h>', dependencies: clock_gettime)
        clock_gettime = cc.find_library('posix4')

        if not cc.has_function('clock_gettime',
                prefix: '#include <time.h>', dependencies: clock_gettime)
            error('clock_gettime not found')
        endif
    endif
endif

foreach function : [
    'posix_memalign',
    'posix_fallocate',
    'explicit_bzero',
]
    conf.set10('HAVE_' + function.underscorify().to_upper(), cc.has_function(function))
endforeach

# no need to enable large file support, as it is on be default in meson
# https://github.com/mesonbuild/meson/commit/853634a48da025c59eef70161dba0d150833f60d

# ==========================================================================
# LUKS2 external tokens

# dl is also required by all-symbols-test
dl = []
if not cc.has_function('dlsym',
        prefix: '#include <dlfcn.h>')
    dl = cc.find_library('dl')

    if not cc.has_function('dlsym',
            prefix: '#include <dlfcn.h>', dependencies: dl)
        error('dlsym not found')
    endif
endif
if cc.has_function('dlvsym',
        dependencies: dl)
    conf.set10('HAVE_DLVSYM', true)
endif

if get_option('external-tokens')
    assert(conf.has('HAVE_DLVSYM') and conf.get('HAVE_DLVSYM') == 1,
        'dl library has no dlvsym function')
    conf.set10('USE_EXTERNAL_TOKENS', true,
        description: 'Use external tokens')
endif

# SSH external tokens
if not get_option('external-tokens') and get_option('ssh-token')
    error('Requested LUKS2 ssh-token build, but external tokens are disabled.')
endif

if get_option('luks2-reencryption')
    conf.set10('USE_LUKS2_REENCRYPTION', true,
        description: 'Use LUKS2 online reencryption extension')
endif

# ==========================================================================

popt = cc.find_library('popt',
    static: enable_static)
assert(cc.has_function('poptConfigFileToString',
        dependencies: popt),
    'You need popt 1.7 or newer to compile.')

# ==========================================================================
# FIPS extensions

if get_option('fips')
    if enable_static
        error('Static build is not compatible with FIPS.')
    endif

    conf.set10('ENABLE_FIPS', true,
        description: 'Enable FIPS mode restrictions')
endif

# ==========================================================================
# pwquality library (cryptsetup CLI only)

pwquality = []
if get_option('pwquality')
    pwquality = dependency('pwquality',
        version: '>= 1.0.0',
        static: enable_static)
    conf.set10('ENABLE_PWQUALITY', true)
endif

# ==========================================================================
# fuzzers, it requires own static library compilation later

if get_option('fuzz-targets')
    assert(sanitizer_enabled,
        'Fuzz targets are only supported with sanitizer enabled. Please set -Db_sanitize')
    add_languages('cpp')

    if get_option('fuzzing-engine') == ''
        fuzzing_engine = meson.get_compiler('cpp').find_library('Fuzzer', required: false)
        if fuzzing_engine.found()
            add_project_arguments('-fsanitize-coverage=trace-pc-guard,trace-cmp',
                language: [ 'c', 'cpp' ])
        elif cc.has_argument( '-fsanitize=fuzzer-no-link',) and cc.has_argument( '-fsanitize=fuzzer',)
            message('Using -fsanitize=fuzzer engine')
            fuzzing_engine = declare_dependency(link_args: ['-fsanitize=fuzzer'])
            add_project_arguments('-fsanitize=fuzzer-no-link',
                language: [ 'c', 'cpp' ])
        else
            error('Looks like neither libFuzzer nor -fsanitize=fuzzer-no-link is supported')
        endif
    else
        fuzzing_engine = declare_dependency(link_args: get_option('fuzzing-engine').split())
    endif

    protobuf = dependency('protobuf',
        required: false)
    protoc = find_program('protoc',
        required: false)
    if not protoc.found()
        protoc = find_program('tests/fuzz/build/static_lib_deps/bin/protoc',
            required: false)
    endif
    if not protoc.found() or not protobuf.found()
        error('protoc tool and/or protobuf pkg-config dependency not found')
    endif

    libprotobuf_mutator = dependency('libprotobuf-mutator',
        required: false)
    if not libprotobuf_mutator.found()
        error('libprotobuf-mutator not found')
    endif

    protoc_generator = generator(protoc,
        output: [
            '@BASENAME@.pb.cc',
            '@BASENAME@.pb.h',
        ],
        arguments: [
            '--proto_path=@CURRENT_SOURCE_DIR@',
            '--cpp_out=@BUILD_DIR@',
            '@INPUT@',
        ])
endif

# ==========================================================================
# passwdqc library (cryptsetup CLI only)

passwdqc_config = ''
use_passwdqc = false
if get_option('passwdqc') == 'true'
    use_passwdqc = true
elif get_option('passwdqc') == 'false'
    use_passwdqc = false
elif get_option('passwdqc').startswith('/')
    use_passwdqc = true
    passwdqc_config = get_option('passwdqc')
else
    error('Unrecognized passwdqc parameter "@0@" (supported options are true, false or absolute path).'
        .format(get_option('passwdqc')))
endif

passwdqc = []
conf.set_quoted('PASSWDQC_CONFIG_FILE', passwdqc_config,
    description: 'passwdqc library config file')
if use_passwdqc
    conf.set10('ENABLE_PASSWDQC', true,
        description: 'Enable password quality checking using passwdqc library')
    #passwdqc = dependency('passwdqc', required : false)
    passwdqc = cc.find_library('passwdqc',
        required: false,
        static: enable_static)
    assert(cc.has_function('passwdqc_check',
            prefix: '#include <passwdqc.h>', dependencies: passwdqc),
        'failed to find passwdqc_check from the passwdqc library')

    assert(cc.has_function('passwdqc_params_free',
            prefix: '#include <passwdqc.h>', dependencies: passwdqc),
        'failed to find passwdqc_params_free from the passwdqc library')

    conf.set10('HAVE_PASSWDQC_PARAMS_FREE', cc.has_function('passwdqc_params_free',
            prefix: '#include <passwdqc.h>', dependencies: passwdqc))
endif

if use_passwdqc and get_option('pwquality')
    error('pwquality and passwdqc are mutually incompatible.')
endif

# ==========================================================================
# libdevmapper

devmapper = dependency('devmapper',
    version: '>= 1.02.03',
    required: false,
    static: enable_static)
if not devmapper.found()
    message('devmapper not found using pkgconf')
    devmapper = cc.find_library('devmapper',
        static: enable_static)
    assert(cc.has_function('dm_task_set_name',
            prefix: '#include <libdevmapper.h>', dependencies: devmapper),
        'You need the device-mapper library.')

    assert(cc.has_function('dm_task_set_message',
            prefix: '#include <libdevmapper.h>', dependencies: devmapper),
        'The device-mapper library on your system is too old.')
endif

foreach function : [
    'dm_device_get_name',
    'dm_device_has_holders',
    'dm_device_has_mounted_fs',
    'dm_task_deferred_remove',
    'dm_task_retry_remove',
    'dm_task_secure_data',
]
    has_function = cc.has_function(function,
        prefix: '#include <libdevmapper.h>', dependencies: devmapper)
    conf.set10('HAVE_DECL_' + function.underscorify().to_upper(), has_function)
endforeach

foreach symbol : [
    'DM_DEVICE_GET_TARGET_VERSION',
    'DM_UDEV_DISABLE_DISK_RULES_FLAG',
]
    has_symbol = cc.has_header_symbol('libdevmapper.h', symbol,
        dependencies: devmapper)
    conf.set10('HAVE_DECL_' + symbol.underscorify().to_upper(), has_symbol)
endforeach

if cc.has_header_symbol('libdevmapper.h', 'DM_UDEV_DISABLE_DISK_RULES_FLAG',
        dependencies: devmapper)
    conf.set10('USE_UDEV', true,
        description: 'Try to use udev synchronisation?')
else
    warning('The device-mapper library on your system has no udev support, udev support disabled.')
endif

# ==========================================================================
# Check for JSON-C used in LUKS2

jsonc = dependency('json-c',
    static: enable_static)
foreach function : [
    'json_object_object_add_ex',
    'json_object_deep_copy',
]
    has_function = cc.has_function(function,
        prefix: '#include <json_object.h>', dependencies: jsonc)
    conf.set10('HAVE_DECL_' + function.underscorify().to_upper(), has_function)
endforeach

# ==========================================================================
# Check for libssh and argp for SSH plugin

if get_option('ssh-token')
    argp = []

    if not cc.has_function('argp_parse', prefix: '#include <argp.h>', dependencies: argp)
        argp = cc.find_library('argp',
            static: enable_static)
    endif

    libssh = dependency('libssh')
    conf.set10('HAVE_DECL_SSH_SESSION_IS_KNOWN_SERVER',
        cc.has_function('ssh_session_is_known_server',
            prefix: '#include <libssh/libssh.h>', dependencies: libssh))
endif

# ==========================================================================
# Crypto backend configuration.

if get_option('kernel_crypto')
    assert(cc.has_header('linux/if_alg.h'),
        'You need Linux kernel headers with userspace crypto interface. (Or use --disable-kernel_crypto.')
    conf.set10('ENABLE_AF_ALG', true,
        description: 'Enable using of kernel userspace crypto')
endif

crypto_backend_library = []
use_internal_pbkdf2 = false
use_internal_argon2 = true

if get_option('crypto-backend') == 'gcrypt'
    req_version = '1.1.42'
    if get_option('fips')
        req_version = '1.4.5'
    endif

    if get_option('gcrypt-pbkdf2').auto()
        # Check if we can use gcrypt PBKDF2 (1.6.0 supports empty password)
        gcrypt_with_empty_password = dependency('libgcrypt',
            version: '>=1.6.1',
            required: false,
            static: enable_static)
        if gcrypt_with_empty_password.found()
            req_version = '1.6.1'
            use_internal_pbkdf2 = false
        else
            use_internal_pbkdf2 = true
        endif
    else
        use_internal_pbkdf2 = get_option('gcrypt-pbkdf2').disabled()
    endif

    if use_internal_pbkdf2 and get_option('fips')
        error('Using internal cryptsetup PBKDF2 is not compatible with FIPS.')
    endif

    if get_option('gcrypt-argon2').auto()
        # Check if we can use gcrypt Argon2 (1.11.0 supports empty password)
        gcrypt_with_empty_password = dependency('libgcrypt',
            version: '>=1.11.0',
            required: false,
            static: enable_static)
        if gcrypt_with_empty_password.found()
            req_version = '1.11.0'
            use_internal_argon2 = false
        else
            use_internal_argon2 = true
        endif
    else
        use_internal_argon2 = get_option('gcrypt-argon2').disabled()
    endif

    crypto_backend_library = dependency('libgcrypt',
        version: '>=@0@'.format(req_version),
        static: enable_static)
    conf.set10('HAVE_DECL_GCRY_CIPHER_MODE_XTS',
        cc.has_header_symbol('gcrypt.h', 'GCRY_CIPHER_MODE_XTS',
            dependencies: crypto_backend_library))
    conf.set10('HAVE_DECL_GCRY_KDF_ARGON2',
        cc.has_header_symbol('gcrypt.h', 'GCRY_KDF_ARGON2',
            dependencies: crypto_backend_library))
    conf.set_quoted('GCRYPT_REQ_VERSION', req_version,
        description: 'Requested gcrypt version')
elif get_option('crypto-backend') == 'openssl'
    use_internal_pbkdf2 = false
    use_internal_argon2 = true
    crypto_backend_library = dependency('libcrypto',
        version: '>=0.9.8',
        static: enable_static)
    conf.set10('HAVE_DECL_OSSL_GET_MAX_THREADS',
        cc.has_header_symbol('openssl/thread.h', 'OSSL_get_max_threads',
            dependencies: crypto_backend_library))
    conf.set10('HAVE_DECL_OSSL_KDF_PARAM_ARGON2_VERSION',
        cc.has_header_symbol('openssl/core_names.h', 'OSSL_KDF_PARAM_ARGON2_VERSION',
            dependencies: crypto_backend_library))
    if conf.get('HAVE_DECL_OSSL_KDF_PARAM_ARGON2_VERSION') == 1
        use_internal_argon2 = false
    endif
elif get_option('crypto-backend') == 'nss'
    if get_option('fips')
        error('nss crypto backend is not supported with FIPS enabled')
    endif
    if enable_static
        error('Static build of cryptsetup is not supported with NSS.')
    endif

    warning('NSS backend does NOT provide backward compatibility (missing ripemd160 hash).')
    use_internal_pbkdf2 = true
    use_internal_argon2 = true

    crypto_backend_library = dependency('nss',
        static: enable_static)
    conf.set10('HAVE_DECL_NSS_GETVERSION',
        cc.has_header_symbol('nss.h', 'NSS_GetVersion',
            dependencies: crypto_backend_library))
elif get_option('crypto-backend') == 'kernel'
    if get_option('fips')
        error('kernel crypto backend is not supported with FIPS enabled')
    endif
    use_internal_pbkdf2 = true
    use_internal_argon2 = true
    assert(cc.has_header('linux/if_alg.h'),
        'You need Linux kernel headers with userspace crypto interface.')
elif get_option('crypto-backend') == 'nettle'
    if get_option('fips')
        error('nettle crypto backend is not supported with FIPS enabled')
    endif
    assert(cc.has_header('nettle/sha.h'),
        'You need Nettle cryptographic library.')
    conf.set10('HAVE_NETTLE_VERSION_H', cc.has_header('nettle/version.h'))

    crypto_backend_library = dependency('nettle',
        static: enable_static)
    use_internal_pbkdf2 = false
    use_internal_argon2 = true
    assert(cc.has_function('nettle_pbkdf2_hmac_sha256',
            dependencies: crypto_backend_library),
        'You need Nettle library version 2.6 or more recent.')
elif get_option('crypto-backend') == 'mbedtls'
    if get_option('fips')
        error('mbedtls crypto backend is not supported with FIPS enabled')
    endif

    assert(cc.has_header('mbedtls/version.h'),
        'You need mbedTLS cryptographic library.')

    mbedcrypto = cc.find_library('mbedcrypto',
        static: enable_static)
    assert(cc.has_function('mbedtls_md_init',
            prefix: '#include <mbedtls/md.h>', dependencies: mbedcrypto),
        'You need mbedcrypto library.')

    conf.set10('HAVE_MBEDTLS_PKCS5_PBKDF2_HMAC_EXT',
        cc.has_function('mbedtls_pkcs5_pbkdf2_hmac_ext',
            prefix: '#include <mbedtls/pkcs5.h>', dependencies: mbedcrypto),
        description: 'Define to 1 if you have the `mbedtls_pkcs5_pbkdf2_hmac_ext\' function.')

    crypto_backend_library = mbedcrypto
    use_internal_pbkdf2 = false
    use_internal_argon2 = true
endif
conf.set10('USE_INTERNAL_PBKDF2', use_internal_pbkdf2)

libargon2_external = []
threads = []
use_internal_sse_argon2 = false
if not use_internal_argon2 or get_option('argon-implementation') == 'none'
    if get_option('argon-implementation') == 'internal' or get_option('argon-implementation') == 'libargon2'
        message('Argon2 in crypto library is used; internal Argon2 options are ignored.')
    endif
    conf.set10('USE_INTERNAL_ARGON2', false,
        description: 'Use internal Argon2.')
elif get_option('argon-implementation') == 'internal'
    warning('Argon2 bundled (slow) reference implementation will be used, please consider using system library with -Dargon-implementation=libargon2')

    if get_option('internal-sse-argon2')
        use_internal_sse_argon2 = cc.links(
            '''#include <emmintrin.h>
		__m128i testfunc(__m128i *a, __m128i *b) {
			return _mm_xor_si128(_mm_loadu_si128(a), _mm_loadu_si128(b));
		}
		int main(int argc, char **argv) { return 0; }''',
            name: 'Argon2 SSE optimization can be used')

        if not use_internal_sse_argon2
            warning('Argon2 SSE optimization cannot be used, disabling.')
        endif
    endif
    conf.set10('USE_INTERNAL_ARGON2', true,
        description: 'Use internal Argon2.')

    threads = dependency('threads')
elif get_option('argon-implementation') == 'libargon2'
    libargon2_external = dependency('libargon2',
        static: enable_static)
    assert(cc.has_header('argon2.h',
            dependencies: libargon2_external),
        'You need libargon2 development library installed.')
    assert(cc.has_header_symbol(
            'argon2.h',
            'Argon2_id',
            dependencies: libargon2_external),
        'You need more recent Argon2 library with support for Argon2id.')
    conf.set10('USE_INTERNAL_ARGON2', false,
        description: 'Use internal Argon2.')
    conf.set10('HAVE_ARGON2_H', true)
endif

# ==========================================================================
# Link with blkid to check for other device types

blkid = []
if get_option('blkid')
    blkid = dependency('blkid',
        static: enable_static)
    assert(cc.has_header('blkid/blkid.h',
            dependencies: blkid),
        'You need blkid development library installed.')

    conf.set10('HAVE_BLKID', true,
        description: 'Define to 1 to use blkid for detection of disk signatures.')
    conf.set10('HAVE_BLKID_WIPE',
        cc.has_function('blkid_do_wipe',
            prefix: '#include <blkid/blkid.h>', dependencies: blkid),
        description: 'Define to 1 to use blkid_do_wipe.')
    conf.set10('HAVE_BLKID_STEP_BACK',
        cc.has_function('blkid_probe_step_back',
            prefix: '#include <blkid/blkid.h>', dependencies: blkid),
        description: 'Define to 1 to use blkid_probe_step_back.')

    foreach header : [
        'blkid_reset_probe',
        'blkid_probe_set_device',
        'blkid_probe_filter_superblocks_type',
        'blkid_do_safeprobe',
        'blkid_do_probe',
        'blkid_probe_lookup_value',
    ]
        assert(cc.has_function(header,
                prefix: '#include <blkid/blkid.h>', dependencies: blkid),
            'Can not compile with blkid support, disable it by -Dblkid=false')
    endforeach
endif

have = get_option('hw-opal')
if have
    if cc.has_header('linux/sed-opal.h')
        foreach symbol : [
            'OPAL_FL_SUM_SUPPORTED',
            'IOC_OPAL_GET_LR_STATUS',
            'IOC_OPAL_GET_GEOMETRY',
        ]
            if not cc.has_header_symbol('linux/sed-opal.h', symbol)
                have = false
                warning('OPAL support disabled, linux/sed-opal.h does not define ' + symbol)
            endif
        endforeach

    else
        have = false
        warning('OPAL support disabled, linux/sed-opal.h not found, requires kernel v6.4.')
    endif
endif
conf.set10('HAVE_HW_OPAL', have, description: 'Define to 1 to enable OPAL support.')


# ==========================================================================
# Check compiler support for symver function attribute

if cc.links(
        '''void _test_sym(void);

         __attribute__((__symver__("sym@VERSION_4.2"))) void _test_sym(void) {}
         int main(int argc, char **argv) { return 0; }''',
        args: ['-O0', '-Werror' ],
        name: 'for symver attribute support')
    conf.set10('HAVE_ATTRIBUTE_SYMVER', true,
        description: 'Define to 1 to use __attribute__((symver))')
endif

# ==========================================================================
# Check compiler support for zero_called_used_regs("used") function attribute
if cc.links(
        '''void _test_fn(void);

        __attribute__((zero_call_used_regs("used"))) void _test_fn(void) {
		volatile int *i; volatile int j = 0; if (j) *i = 0;
        }
        int main(void) { _test_fn(); return 0; }''',
        args: ['-O0', '-Werror' ],
        name: 'for zero_call_used_regs("used") attribute support')
    conf.set10('HAVE_ATTRIBUTE_ZEROCALLUSEDREGS', true,
        description: 'Define to 1 to use __attribute__((zero_call_used_regs("used")))')
endif

# ==========================================================================

if get_option('dev-random')
    conf.set_quoted('DEFAULT_RNG', '/dev/random')
else
    conf.set_quoted('DEFAULT_RNG', '/dev/urandom')
endif

tmpfilesdir = get_option('tmpfilesdir')
if tmpfilesdir == ''
    systemd = dependency('systemd',
        method: 'pkg-config',
        required: false)
    if systemd.found()
        tmpfilesdir = systemd.get_variable('tmpfilesdir',
                        pkgconfig_define: ['prefix', get_option('prefix')],
                        default_value: '')
    endif
endif

if tmpfilesdir != ''
    assert(tmpfilesdir.startswith('/',),
        'tmpfilesdir has to be an absolute path')
endif

# ==========================================================================

if get_option('luks_adjust_xts_keysize')
    conf.set10('ENABLE_LUKS_ADJUST_XTS_KEYSIZE', true,
        description: 'XTS mode - double default LUKS keysize if needed')
endif

assert(get_option('default-luks2-lock-path').startswith('/'),
    'default-luks2-lock-path has to be an absolute path')

luks2_external_tokens_path = get_option('luks2-external-tokens-path')
if luks2_external_tokens_path == ''
    luks2_external_tokens_path = join_paths(get_option('prefix'), get_option('libdir'), 'cryptsetup')
endif
assert(luks2_external_tokens_path.startswith('/'),
    'luks2-external-tokens-path has to be an absolute path')
conf.set_quoted('EXTERNAL_LUKS2_TOKENS_PATH', luks2_external_tokens_path,
    description: 'path to directory with LUKSv2 external token handlers (plugins)')

if get_option('default-luks-format') == 'LUKS1'
    conf.set('DEFAULT_LUKS_FORMAT', 'CRYPT_LUKS1')
elif get_option('default-luks-format') == 'LUKS2'
    conf.set('DEFAULT_LUKS_FORMAT', 'CRYPT_LUKS2')
else
    error('Unknown default LUKS format. Use LUKS1 or LUKS2 only.')
endif

# ==========================================================================

if get_option('nls')
    conf.set10('ENABLE_NLS', true)
    assert(find_program('gettext').found(),
        'You need gettext binary to build translations.')
endif

# ==========================================================================

configure_file(
    output: 'config.h',
    configuration: conf,
)
add_project_arguments('-include', 'config.h',
    language: 'c')

subdir('lib')
subdir('man')
subdir('po')
subdir('src')
subdir('scripts')
subdir('tokens')
subdir('tests')
