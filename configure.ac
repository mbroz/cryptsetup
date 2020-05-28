AC_PREREQ([2.67])
AC_INIT([cryptsetup],[2.3.3])

dnl library version from <major>.<minor>.<release>[-<suffix>]
LIBCRYPTSETUP_VERSION=$(echo $PACKAGE_VERSION | cut -f1 -d-)
LIBCRYPTSETUP_VERSION_INFO=18:0:6

AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR(src/cryptsetup.c)
AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_HEADERS([config.h:config.h.in])

# We do not want to run test in parallel. Really.
# http://lists.gnu.org/archive/html/automake/2013-01/msg00060.html

# For old automake use this
#AM_INIT_AUTOMAKE(dist-xz subdir-objects)
AM_INIT_AUTOMAKE([dist-xz 1.12 serial-tests subdir-objects])

if test "x$prefix" = "xNONE"; then
	sysconfdir=/etc
fi
AC_PREFIX_DEFAULT(/usr)

AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_ENABLE_STATIC(no)
LT_INIT
PKG_PROG_PKG_CONFIG
AM_ICONV

dnl ==========================================================================
dnl define PKG_CHECK_VAR for old pkg-config <= 0.28
m4_ifndef([AS_VAR_COPY],
[m4_define([AS_VAR_COPY],
[AS_LITERAL_IF([$1[]$2], [$1=$$2], [eval $1=\$$2])])
])
m4_ifndef([PKG_CHECK_VAR], [
AC_DEFUN([PKG_CHECK_VAR],
[AC_REQUIRE([PKG_PROG_PKG_CONFIG])
AC_ARG_VAR([$1], [value of $3 for $2, overriding pkg-config])

_PKG_CONFIG([$1], [variable="][$3]["], [$2])
AS_VAR_COPY([$1], [pkg_cv_][$1])

AS_VAR_IF([$1], [""], [$5], [$4])
])
])
dnl ==========================================================================

AC_C_RESTRICT

AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h malloc.h inttypes.h sys/ioctl.h sys/mman.h \
	sys/sysmacros.h sys/statvfs.h ctype.h unistd.h locale.h byteswap.h endian.h stdint.h)
AC_CHECK_DECLS([O_CLOEXEC],,[AC_DEFINE([O_CLOEXEC],[0], [Defined to 0 if not provided])],
[[
#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
]])

AC_CHECK_HEADERS(uuid/uuid.h,,[AC_MSG_ERROR([You need the uuid library.])])
AC_CHECK_HEADER(libdevmapper.h,,[AC_MSG_ERROR([You need the device-mapper library.])])

AC_ARG_ENABLE([keyring],
	AS_HELP_STRING([--disable-keyring], [disable kernel keyring support and builtin kernel keyring token]),
	[], [enable_keyring=yes])
if test "x$enable_keyring" = "xyes"; then
	AC_CHECK_HEADERS(linux/keyctl.h,,[AC_MSG_ERROR([You need Linux kernel headers with kernel keyring service compiled.])])

	dnl ==========================================================================
	dnl check whether kernel is compiled with kernel keyring service syscalls
	AC_CHECK_DECL(__NR_add_key,,[AC_MSG_ERROR([The kernel is missing add_key syscall.])], [#include <syscall.h>])
	AC_CHECK_DECL(__NR_keyctl,,[AC_MSG_ERROR([The kernel is missing keyctl syscall.])], [#include <syscall.h>])
	AC_CHECK_DECL(__NR_request_key,,[AC_MSG_ERROR([The kernel is missing request_key syscall.])], [#include <syscall.h>])

	dnl ==========================================================================
	dnl check that key_serial_t hasn't been adopted yet in stdlib
	AC_CHECK_TYPES([key_serial_t], [], [], [
	AC_INCLUDES_DEFAULT
	#ifdef HAVE_LINUX_KEYCTL_H
	# include <linux/keyctl.h>
	#endif
	])

	AC_DEFINE(KERNEL_KEYRING, 1, [Enable kernel keyring service support])
fi
AM_CONDITIONAL(KERNEL_KEYRING, test "x$enable_keyring" = "xyes")

saved_LIBS=$LIBS
AC_CHECK_LIB(uuid, uuid_clear, ,[AC_MSG_ERROR([You need the uuid library.])])
AC_SUBST(UUID_LIBS, $LIBS)
LIBS=$saved_LIBS

AC_SEARCH_LIBS([clock_gettime],[rt posix4])
AC_CHECK_FUNCS([posix_memalign clock_gettime posix_fallocate explicit_bzero])

if test "x$enable_largefile" = "xno"; then
  AC_MSG_ERROR([Building with --disable-largefile is not supported, it can cause data corruption.])
fi

AC_C_CONST
AC_C_BIGENDIAN
AC_TYPE_OFF_T
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO
AC_PROG_GCC_TRADITIONAL
AC_FUNC_STRERROR_R

dnl ==========================================================================

AM_GNU_GETTEXT([external],[need-ngettext])
AM_GNU_GETTEXT_VERSION([0.18.3])

dnl ==========================================================================

saved_LIBS=$LIBS
AC_CHECK_LIB(popt, poptConfigFileToString,,
	[AC_MSG_ERROR([You need popt 1.7 or newer to compile.])])
AC_SUBST(POPT_LIBS, $LIBS)
LIBS=$saved_LIBS

dnl ==========================================================================
dnl FIPS extensions
AC_ARG_ENABLE([fips],
	AS_HELP_STRING([--enable-fips], [enable FIPS mode restrictions]))
if test "x$enable_fips" = "xyes"; then
	AC_DEFINE(ENABLE_FIPS, 1, [Enable FIPS mode restrictions])

	if test "x$enable_static" = "xyes" -o "x$enable_static_cryptsetup" = "xyes" ; then
		AC_MSG_ERROR([Static build is not compatible with FIPS.])
	fi
fi

AC_DEFUN([NO_FIPS], [
	if test "x$enable_fips" = "xyes"; then
		AC_MSG_ERROR([This option is not compatible with FIPS.])
	fi
])

dnl ==========================================================================
dnl pwquality library (cryptsetup CLI only)
AC_ARG_ENABLE([pwquality],
	AS_HELP_STRING([--enable-pwquality], [enable password quality checking using pwquality library]))

if test "x$enable_pwquality" = "xyes"; then
	AC_DEFINE(ENABLE_PWQUALITY, 1, [Enable password quality checking using pwquality library])
	PKG_CHECK_MODULES([PWQUALITY], [pwquality >= 1.0.0],,
		AC_MSG_ERROR([You need pwquality library.]))

	dnl FIXME: this is really hack for now
	PWQUALITY_STATIC_LIBS="$PWQUALITY_LIBS -lcrack -lz"
fi

dnl ==========================================================================
dnl passwdqc library (cryptsetup CLI only)
AC_ARG_ENABLE([passwdqc],
	AS_HELP_STRING([--enable-passwdqc@<:@=CONFIG_PATH@:>@],
		       [enable password quality checking using passwdqc library (optionally with CONFIG_PATH)]))

case "$enable_passwdqc" in
	""|yes|no) use_passwdqc_config="" ;;
	/*) use_passwdqc_config="$enable_passwdqc"; enable_passwdqc=yes ;;
	*) AC_MSG_ERROR([Unrecognized --enable-passwdqc parameter.]) ;;
esac
AC_DEFINE_UNQUOTED([PASSWDQC_CONFIG_FILE], ["$use_passwdqc_config"], [passwdqc library config file])

if test "x$enable_passwdqc" = "xyes"; then
	AC_DEFINE(ENABLE_PASSWDQC, 1, [Enable password quality checking using passwdqc library])

	PASSWDQC_LIBS="-lpasswdqc"
fi

if test "x$enable_pwquality$enable_passwdqc" = "xyesyes"; then
	AC_MSG_ERROR([--enable-pwquality and --enable-passwdqc are mutually incompatible.])
fi

dnl ==========================================================================
dnl Crypto backend functions

AC_DEFUN([CONFIGURE_GCRYPT], [
	if test "x$enable_fips" = "xyes"; then
		GCRYPT_REQ_VERSION=1.4.5
	else
		GCRYPT_REQ_VERSION=1.1.42
	fi

	dnl libgcrypt rejects to use pkgconfig, use AM_PATH_LIBGCRYPT from gcrypt-devel here.
	dnl Do not require gcrypt-devel if other crypto backend is used.
	m4_ifdef([AM_PATH_LIBGCRYPT],[
	AC_ARG_ENABLE([gcrypt-pbkdf2],
		dnl Check if we can use gcrypt PBKDF2 (1.6.0 supports empty password)
		AS_HELP_STRING([--enable-gcrypt-pbkdf2], [force enable internal gcrypt PBKDF2]),
		if test "x$enableval" = "xyes"; then
			[use_internal_pbkdf2=0]
		else
			[use_internal_pbkdf2=1]
		fi,
		[AM_PATH_LIBGCRYPT([1.6.1], [use_internal_pbkdf2=0], [use_internal_pbkdf2=1])])
	AM_PATH_LIBGCRYPT($GCRYPT_REQ_VERSION,,[AC_MSG_ERROR([You need the gcrypt library.])])],
	AC_MSG_ERROR([Missing support for gcrypt: install gcrypt and regenerate configure.]))

	AC_MSG_CHECKING([if internal cryptsetup PBKDF2 is compiled-in])
	if test $use_internal_pbkdf2 = 0; then
		AC_MSG_RESULT([no])
	else
		AC_MSG_RESULT([yes])
		NO_FIPS([])
	fi

	AC_CHECK_DECLS([GCRY_CIPHER_MODE_XTS], [], [], [#include <gcrypt.h>])

	if test "x$enable_static_cryptsetup" = "xyes"; then
		saved_LIBS=$LIBS
		LIBS="$saved_LIBS $LIBGCRYPT_LIBS -static"
		AC_CHECK_LIB(gcrypt, gcry_check_version,,
			AC_MSG_ERROR([Cannot find static gcrypt library.]),
			[-lgpg-error])
		LIBGCRYPT_STATIC_LIBS="$LIBGCRYPT_LIBS -lgpg-error"
		LIBS=$saved_LIBS
        fi

	CRYPTO_CFLAGS=$LIBGCRYPT_CFLAGS
	CRYPTO_LIBS=$LIBGCRYPT_LIBS
	CRYPTO_STATIC_LIBS=$LIBGCRYPT_STATIC_LIBS

	AC_DEFINE_UNQUOTED(GCRYPT_REQ_VERSION, ["$GCRYPT_REQ_VERSION"], [Requested gcrypt version])
])

AC_DEFUN([CONFIGURE_OPENSSL], [
	PKG_CHECK_MODULES([OPENSSL], [openssl >= 0.9.8],,
		AC_MSG_ERROR([You need openssl library.]))
	CRYPTO_CFLAGS=$OPENSSL_CFLAGS
	CRYPTO_LIBS=$OPENSSL_LIBS
	use_internal_pbkdf2=0

	if test "x$enable_static_cryptsetup" = "xyes"; then
		saved_PKG_CONFIG=$PKG_CONFIG
		PKG_CONFIG="$PKG_CONFIG --static"
		PKG_CHECK_MODULES([OPENSSL_STATIC], [openssl])
		CRYPTO_STATIC_LIBS=$OPENSSL_STATIC_LIBS
		PKG_CONFIG=$saved_PKG_CONFIG
	fi
])

AC_DEFUN([CONFIGURE_NSS], [
	if test "x$enable_static_cryptsetup" = "xyes"; then
		AC_MSG_ERROR([Static build of cryptsetup is not supported with NSS.])
	fi

	AC_MSG_WARN([NSS backend does NOT provide backward compatibility (missing ripemd160 hash).])

	PKG_CHECK_MODULES([NSS], [nss],,
		AC_MSG_ERROR([You need nss library.]))

	saved_CFLAGS=$CFLAGS
	CFLAGS="$CFLAGS $NSS_CFLAGS"
	AC_CHECK_DECLS([NSS_GetVersion], [], [], [#include <nss.h>])
	CFLAGS=$saved_CFLAGS

	CRYPTO_CFLAGS=$NSS_CFLAGS
	CRYPTO_LIBS=$NSS_LIBS
	use_internal_pbkdf2=1
	NO_FIPS([])
])

AC_DEFUN([CONFIGURE_KERNEL], [
	AC_CHECK_HEADERS(linux/if_alg.h,,
		[AC_MSG_ERROR([You need Linux kernel headers with userspace crypto interface.])])
#	AC_CHECK_DECLS([AF_ALG],,
#		[AC_MSG_ERROR([You need Linux kernel with userspace crypto interface.])],
#		[#include <sys/socket.h>])
	use_internal_pbkdf2=1
	NO_FIPS([])
])

AC_DEFUN([CONFIGURE_NETTLE], [
	AC_CHECK_HEADERS(nettle/sha.h,,
		[AC_MSG_ERROR([You need Nettle cryptographic library.])])
	AC_CHECK_HEADERS(nettle/version.h)

	saved_LIBS=$LIBS
	AC_CHECK_LIB(nettle, nettle_pbkdf2_hmac_sha256,,
		[AC_MSG_ERROR([You need Nettle library version 2.6 or more recent.])])
	CRYPTO_LIBS=$LIBS
	LIBS=$saved_LIBS

	CRYPTO_STATIC_LIBS=$CRYPTO_LIBS
	use_internal_pbkdf2=0
	NO_FIPS([])
])

dnl ==========================================================================
saved_LIBS=$LIBS

AC_ARG_ENABLE([static-cryptsetup],
	AS_HELP_STRING([--enable-static-cryptsetup], [enable build of static version of tools]))
if test "x$enable_static_cryptsetup" = "xyes"; then
	if test "x$enable_static" = "xno"; then
		AC_MSG_WARN([Requested static cryptsetup build, enabling static library.])
		enable_static=yes
	fi
fi
AM_CONDITIONAL(STATIC_TOOLS, test "x$enable_static_cryptsetup" = "xyes")

AC_ARG_ENABLE([cryptsetup],
	AS_HELP_STRING([--disable-cryptsetup], [disable cryptsetup support]),
	[], [enable_cryptsetup=yes])
AM_CONDITIONAL(CRYPTSETUP, test "x$enable_cryptsetup" = "xyes")

AC_ARG_ENABLE([veritysetup],
	AS_HELP_STRING([--disable-veritysetup], [disable veritysetup support]),
	[], [enable_veritysetup=yes])
AM_CONDITIONAL(VERITYSETUP, test "x$enable_veritysetup" = "xyes")

AC_ARG_ENABLE([cryptsetup-reencrypt],
	AS_HELP_STRING([--disable-cryptsetup-reencrypt], [disable cryptsetup-reencrypt tool]),
	[], [enable_cryptsetup_reencrypt=yes])
AM_CONDITIONAL(REENCRYPT, test "x$enable_cryptsetup_reencrypt" = "xyes")

AC_ARG_ENABLE([integritysetup],
	AS_HELP_STRING([--disable-integritysetup], [disable integritysetup support]),
	[], [enable_integritysetup=yes])
AM_CONDITIONAL(INTEGRITYSETUP, test "x$enable_integritysetup" = "xyes")

AC_ARG_ENABLE([selinux],
	AS_HELP_STRING([--disable-selinux], [disable selinux support [default=auto]]),
	[], [enable_selinux=yes])

AC_ARG_ENABLE([udev],
	AS_HELP_STRING([--disable-udev], [disable udev support]),
	[], [enable_udev=yes])

dnl Try to use pkg-config for devmapper, but fallback to old detection
PKG_CHECK_MODULES([DEVMAPPER], [devmapper >= 1.02.03],, [
	AC_CHECK_LIB(devmapper, dm_task_set_name,,
		[AC_MSG_ERROR([You need the device-mapper library.])])
	AC_CHECK_LIB(devmapper, dm_task_set_message,,
		[AC_MSG_ERROR([The device-mapper library on your system is too old.])])
	DEVMAPPER_LIBS=$LIBS
])
LIBS=$saved_LIBS

LIBS="$LIBS $DEVMAPPER_LIBS"
AC_CHECK_DECLS([dm_task_secure_data], [], [], [#include <libdevmapper.h>])
AC_CHECK_DECLS([dm_task_retry_remove], [], [], [#include <libdevmapper.h>])
AC_CHECK_DECLS([dm_task_deferred_remove], [], [], [#include <libdevmapper.h>])
AC_CHECK_DECLS([dm_device_has_mounted_fs], [], [], [#include <libdevmapper.h>])
AC_CHECK_DECLS([dm_device_has_holders], [], [], [#include <libdevmapper.h>])
AC_CHECK_DECLS([dm_device_get_name], [], [], [#include <libdevmapper.h>])
AC_CHECK_DECLS([DM_DEVICE_GET_TARGET_VERSION], [], [], [#include <libdevmapper.h>])
AC_CHECK_DECLS([DM_UDEV_DISABLE_DISK_RULES_FLAG], [have_cookie=yes], [have_cookie=no], [#include <libdevmapper.h>])
if test "x$enable_udev" = xyes; then
	if test "x$have_cookie" = xno; then
		AC_MSG_WARN([The device-mapper library on your system has no udev support, udev support disabled.])
	else
		AC_DEFINE(USE_UDEV, 1, [Try to use udev synchronisation?])
	fi
fi
LIBS=$saved_LIBS

dnl Check for JSON-C used in LUKS2
PKG_CHECK_MODULES([JSON_C], [json-c])
AC_CHECK_DECLS([json_object_object_add_ex], [], [], [#include <json-c/json.h>])
AC_CHECK_DECLS([json_object_deep_copy], [], [], [#include <json-c/json.h>])

dnl Crypto backend configuration.
AC_ARG_WITH([crypto_backend],
	AS_HELP_STRING([--with-crypto_backend=BACKEND], [crypto backend (gcrypt/openssl/nss/kernel/nettle) [openssl]]),
	[], [with_crypto_backend=openssl])

dnl Kernel crypto API backend needed for benchmark and tcrypt
AC_ARG_ENABLE([kernel_crypto],
	AS_HELP_STRING([--disable-kernel_crypto], [disable kernel userspace crypto (no benchmark and tcrypt)]),
	[], [enable_kernel_crypto=yes])

if test "x$enable_kernel_crypto" = "xyes"; then
	AC_CHECK_HEADERS(linux/if_alg.h,,
		[AC_MSG_ERROR([You need Linux kernel headers with userspace crypto interface. (Or use --disable-kernel_crypto.)])])
	AC_DEFINE(ENABLE_AF_ALG, 1, [Enable using of kernel userspace crypto])
fi

case $with_crypto_backend in
	gcrypt)  CONFIGURE_GCRYPT([]) ;;
	openssl) CONFIGURE_OPENSSL([]) ;;
	nss)     CONFIGURE_NSS([]) ;;
	kernel)  CONFIGURE_KERNEL([]) ;;
	nettle)  CONFIGURE_NETTLE([]) ;;
	*) AC_MSG_ERROR([Unknown crypto backend.]) ;;
esac
AM_CONDITIONAL(CRYPTO_BACKEND_GCRYPT,  test "$with_crypto_backend" = "gcrypt")
AM_CONDITIONAL(CRYPTO_BACKEND_OPENSSL, test "$with_crypto_backend" = "openssl")
AM_CONDITIONAL(CRYPTO_BACKEND_NSS,     test "$with_crypto_backend" = "nss")
AM_CONDITIONAL(CRYPTO_BACKEND_KERNEL,  test "$with_crypto_backend" = "kernel")
AM_CONDITIONAL(CRYPTO_BACKEND_NETTLE,  test "$with_crypto_backend" = "nettle")

AM_CONDITIONAL(CRYPTO_INTERNAL_PBKDF2, test $use_internal_pbkdf2 = 1)
AC_DEFINE_UNQUOTED(USE_INTERNAL_PBKDF2, [$use_internal_pbkdf2], [Use internal PBKDF2])

dnl Argon2 implementation
AC_ARG_ENABLE([internal-argon2],
	AS_HELP_STRING([--disable-internal-argon2], [disable internal implementation of Argon2 PBKDF]),
	[], [enable_internal_argon2=yes])

AC_ARG_ENABLE([libargon2],
	AS_HELP_STRING([--enable-libargon2], [enable external libargon2 (PHC) library (disables internal bundled version)]))

if test "x$enable_libargon2" = "xyes" ; then
	AC_CHECK_HEADERS(argon2.h,,
		[AC_MSG_ERROR([You need libargon2 development library installed.])])
	AC_CHECK_DECL(Argon2_id,,[AC_MSG_ERROR([You need more recent Argon2 library with support for Argon2id.])], [#include <argon2.h>])
	PKG_CHECK_MODULES([LIBARGON2], [libargon2],,[LIBARGON2_LIBS="-largon2"])
	enable_internal_argon2=no
else
	AC_MSG_WARN([Argon2 bundled (slow) reference implementation will be used, please consider to use system library with --enable-libargon2.])

	AC_ARG_ENABLE([internal-sse-argon2],
		AS_HELP_STRING([--enable-internal-sse-argon2], [enable internal SSE implementation of Argon2 PBKDF]))

	if test "x$enable_internal_sse_argon2" = "xyes"; then
		AC_MSG_CHECKING(if Argon2 SSE optimization can be used)
		AC_LINK_IFELSE([AC_LANG_PROGRAM([[
			#include <emmintrin.h>
			__m128i testfunc(__m128i *a, __m128i *b) {
			  return _mm_xor_si128(_mm_loadu_si128(a), _mm_loadu_si128(b));
			}
		]])],,[enable_internal_sse_argon2=no])
		AC_MSG_RESULT($enable_internal_sse_argon2)
	fi
fi

if test "x$enable_internal_argon2" = "xyes"; then
	AC_DEFINE(USE_INTERNAL_ARGON2, 1, [Use internal Argon2])
fi
AM_CONDITIONAL(CRYPTO_INTERNAL_ARGON2, test "x$enable_internal_argon2" = "xyes")
AM_CONDITIONAL(CRYPTO_INTERNAL_SSE_ARGON2, test "x$enable_internal_sse_argon2" = "xyes")

dnl Link with blkid to check for other device types
AC_ARG_ENABLE([blkid],
	AS_HELP_STRING([--disable-blkid], [disable use of blkid for device signature detection and wiping]),
	[], [enable_blkid=yes])

if test "x$enable_blkid" = "xyes"; then
	PKG_CHECK_MODULES([BLKID], [blkid],[AC_DEFINE([HAVE_BLKID], 1, [Define to 1 to use blkid for detection of disk signatures.])],[LIBBLKID_LIBS="-lblkid"])

	AC_CHECK_HEADERS(blkid/blkid.h,,[AC_MSG_ERROR([You need blkid development library installed.])])
	AC_CHECK_DECL([blkid_do_wipe],
		      [ AC_DEFINE([HAVE_BLKID_WIPE], 1, [Define to 1 to use blkid_do_wipe.])
			enable_blkid_wipe=yes
		      ],,
		      [#include <blkid/blkid.h>])
	AC_CHECK_DECL([blkid_probe_step_back],
		      [ AC_DEFINE([HAVE_BLKID_STEP_BACK], 1, [Define to 1 to use blkid_probe_step_back.])
			enable_blkid_step_back=yes
		      ],,
		      [#include <blkid/blkid.h>])
	AC_CHECK_DECLS([ blkid_reset_probe,
			 blkid_probe_set_device,
			 blkid_probe_filter_superblocks_type,
			 blkid_do_safeprobe,
			 blkid_do_probe,
			 blkid_probe_lookup_value
		       ],,
		       [AC_MSG_ERROR([Can not compile with blkid support, disable it by --disable-blkid.])],
		       [#include <blkid/blkid.h>])
fi
AM_CONDITIONAL(HAVE_BLKID, test "x$enable_blkid" = "xyes")
AM_CONDITIONAL(HAVE_BLKID_WIPE, test "x$enable_blkid_wipe" = "xyes")
AM_CONDITIONAL(HAVE_BLKID_STEP_BACK, test "x$enable_blkid_step_back" = "xyes")

dnl Magic for cryptsetup.static build.
if test "x$enable_static_cryptsetup" = "xyes"; then
	saved_PKG_CONFIG=$PKG_CONFIG
	PKG_CONFIG="$PKG_CONFIG --static"

	LIBS="$saved_LIBS -static"
	AC_CHECK_LIB(popt, poptGetContext,,
		AC_MSG_ERROR([Cannot find static popt library.]))

	dnl Try to detect needed device-mapper static libraries, try pkg-config first.
	LIBS="$saved_LIBS -static"
	PKG_CHECK_MODULES([DEVMAPPER_STATIC], [devmapper >= 1.02.27],,[
		DEVMAPPER_STATIC_LIBS=$DEVMAPPER_LIBS
		if test "x$enable_selinux" = "xyes"; then
			AC_CHECK_LIB(sepol, sepol_bool_set)
			AC_CHECK_LIB(selinux, is_selinux_enabled)
			DEVMAPPER_STATIC_LIBS="$DEVMAPPER_STATIC_LIBS $LIBS"
		fi
	])
	LIBS="$saved_LIBS $DEVMAPPER_STATIC_LIBS"
	AC_CHECK_LIB(devmapper, dm_task_set_uuid,,
		AC_MSG_ERROR([Cannot link with static device-mapper library.]))

	dnl Try to detect uuid static library.
	LIBS="$saved_LIBS -static"
	AC_CHECK_LIB(uuid, uuid_generate,,
		AC_MSG_ERROR([Cannot find static uuid library.]))

	LIBS=$saved_LIBS
	PKG_CONFIG=$saved_PKG_CONFIG
fi

AC_MSG_CHECKING([for systemd tmpfiles config directory])
PKG_CHECK_VAR([systemd_tmpfilesdir], [systemd], [tmpfilesdir], [], [systemd_tmpfilesdir=no])
AC_MSG_RESULT([$systemd_tmpfilesdir])

AC_SUBST([DEVMAPPER_LIBS])
AC_SUBST([DEVMAPPER_STATIC_LIBS])

AC_SUBST([PWQUALITY_LIBS])
AC_SUBST([PWQUALITY_STATIC_LIBS])

AC_SUBST([PASSWDQC_LIBS])

AC_SUBST([CRYPTO_CFLAGS])
AC_SUBST([CRYPTO_LIBS])
AC_SUBST([CRYPTO_STATIC_LIBS])

AC_SUBST([JSON_C_LIBS])
AC_SUBST([LIBARGON2_LIBS])
AC_SUBST([BLKID_LIBS])

AC_SUBST([LIBCRYPTSETUP_VERSION])
AC_SUBST([LIBCRYPTSETUP_VERSION_INFO])

dnl ==========================================================================
AC_ARG_ENABLE([dev-random],
	AS_HELP_STRING([--enable-dev-random], [use /dev/random by default for key generation (otherwise use /dev/urandom)]))
if test "x$enable_dev_random" = "xyes"; then
	default_rng=/dev/random
else
	default_rng=/dev/urandom
fi
AC_DEFINE_UNQUOTED(DEFAULT_RNG, ["$default_rng"], [default RNG type for key generator])

dnl ==========================================================================
AC_DEFUN([CS_DEFINE],
	[AC_DEFINE_UNQUOTED(DEFAULT_[]m4_translit([$1], [-a-z], [_A-Z]), [$2], [$3])
])

AC_DEFUN([CS_STR_WITH], [AC_ARG_WITH([$1],
	[AS_HELP_STRING(--with-[$1], [default $2 [$3]])],
	[CS_DEFINE([$1], ["$withval"], [$2])],
	[CS_DEFINE([$1], ["$3"], [$2])]
)])

AC_DEFUN([CS_NUM_WITH], [AC_ARG_WITH([$1],
	[AS_HELP_STRING(--with-[$1], [default $2 [$3]])],
	[CS_DEFINE([$1], [$withval], [$2])],
	[CS_DEFINE([$1], [$3], [$2])]
)])

AC_DEFUN([CS_ABSPATH], [
	case "$1" in
		/*) ;;
		*) AC_MSG_ERROR([$2 argument must be an absolute path.]);;
	esac
])

dnl ==========================================================================
CS_STR_WITH([plain-hash],   [password hashing function for plain mode], [ripemd160])
CS_STR_WITH([plain-cipher], [cipher for plain mode], [aes])
CS_STR_WITH([plain-mode],   [cipher mode for plain mode], [cbc-essiv:sha256])
CS_NUM_WITH([plain-keybits],[key length in bits for plain mode], [256])

CS_STR_WITH([luks1-hash],   [hash function for LUKS1 header], [sha256])
CS_STR_WITH([luks1-cipher], [cipher for LUKS1], [aes])
CS_STR_WITH([luks1-mode],   [cipher mode for LUKS1], [xts-plain64])
CS_NUM_WITH([luks1-keybits],[key length in bits for LUKS1], [256])

AC_ARG_ENABLE([luks_adjust_xts_keysize], AS_HELP_STRING([--disable-luks-adjust-xts-keysize],
	[XTS mode requires two keys, double default LUKS keysize if needed]),
	[], [enable_luks_adjust_xts_keysize=yes])
if test "x$enable_luks_adjust_xts_keysize" = "xyes"; then
	AC_DEFINE(ENABLE_LUKS_ADJUST_XTS_KEYSIZE, 1, [XTS mode - double default LUKS keysize if needed])
fi

CS_STR_WITH([luks2-pbkdf],           [Default PBKDF algorithm (pbkdf2 or argon2i/argon2id) for LUKS2], [argon2i])
CS_NUM_WITH([luks1-iter-time],       [PBKDF2 iteration time for LUKS1 (in ms)], [2000])
CS_NUM_WITH([luks2-iter-time],       [Argon2 PBKDF iteration time for LUKS2 (in ms)], [2000])
CS_NUM_WITH([luks2-memory-kb],       [Argon2 PBKDF memory cost for LUKS2 (in kB)], [1048576])
CS_NUM_WITH([luks2-parallel-threads],[Argon2 PBKDF max parallel cost for LUKS2 (if CPUs available)], [4])

CS_STR_WITH([luks2-keyslot-cipher], [fallback cipher for LUKS2 keyslot (if data encryption is incompatible)], [aes-xts-plain64])
CS_NUM_WITH([luks2-keyslot-keybits],[fallback key size for LUKS2 keyslot (if data encryption is incompatible)], [512])

CS_STR_WITH([loopaes-cipher], [cipher for loop-AES mode], [aes])
CS_NUM_WITH([loopaes-keybits],[key length in bits for loop-AES mode], [256])

CS_NUM_WITH([keyfile-size-maxkb],[maximum keyfile size (in KiB)], [8192])
CS_NUM_WITH([passphrase-size-max],[maximum keyfile size (in characters)], [512])

CS_STR_WITH([verity-hash],       [hash function for verity mode], [sha256])
CS_NUM_WITH([verity-data-block], [data block size for verity mode], [4096])
CS_NUM_WITH([verity-hash-block], [hash block size for verity mode], [4096])
CS_NUM_WITH([verity-salt-size],  [salt size for verity mode], [32])
CS_NUM_WITH([verity-fec-roots],  [parity bytes for verity FEC], [2])

CS_STR_WITH([tmpfilesdir], [override default path to directory with systemd temporary files], [])
test -z "$with_tmpfilesdir" && with_tmpfilesdir=$systemd_tmpfilesdir
test "x$with_tmpfilesdir" = "xno" || {
	CS_ABSPATH([${with_tmpfilesdir}],[with-tmpfilesdir])
	DEFAULT_TMPFILESDIR=$with_tmpfilesdir
	AC_SUBST(DEFAULT_TMPFILESDIR)
}
AM_CONDITIONAL(CRYPTSETUP_TMPFILE, test -n "$DEFAULT_TMPFILESDIR")

CS_STR_WITH([luks2-lock-path], [path to directory for LUKSv2 locks], [/run/cryptsetup])
test -z "$with_luks2_lock_path" && with_luks2_lock_path=/run/cryptsetup
CS_ABSPATH([${with_luks2_lock_path}],[with-luks2-lock-path])
DEFAULT_LUKS2_LOCK_PATH=$with_luks2_lock_path
AC_SUBST(DEFAULT_LUKS2_LOCK_PATH)

CS_NUM_WITH([luks2-lock-dir-perms], [default luks2 locking directory permissions], [0700])
test -z "$with_luks2_lock_dir_perms" && with_luks2_lock_dir_perms=0700
DEFAULT_LUKS2_LOCK_DIR_PERMS=$with_luks2_lock_dir_perms
AC_SUBST(DEFAULT_LUKS2_LOCK_DIR_PERMS)

dnl Override default LUKS format version (for cryptsetup or cryptsetup-reencrypt format actions only).
AC_ARG_WITH([default_luks_format],
	AS_HELP_STRING([--with-default-luks-format=FORMAT], [default LUKS format version (LUKS1/LUKS2) [LUKS2]]),
	[], [with_default_luks_format=LUKS2])

case $with_default_luks_format in
	LUKS1) default_luks=CRYPT_LUKS1 ;;
	LUKS2) default_luks=CRYPT_LUKS2 ;;
	*) AC_MSG_ERROR([Unknown default LUKS format. Use LUKS1 or LUKS2 only.]) ;;
esac
AC_DEFINE_UNQUOTED([DEFAULT_LUKS_FORMAT], [$default_luks], [default LUKS format version])

dnl ==========================================================================

AC_CONFIG_FILES([ Makefile
lib/libcryptsetup.pc
po/Makefile.in
scripts/cryptsetup.conf
tests/Makefile
])
AC_OUTPUT
