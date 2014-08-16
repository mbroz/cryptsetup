AC_PREREQ([2.67])
AC_INIT([cryptsetup],[1.6.6])

dnl library version from <major>.<minor>.<release>[-<suffix>]
LIBCRYPTSETUP_VERSION=$(echo $PACKAGE_VERSION | cut -f1 -d-)
LIBCRYPTSETUP_VERSION_INFO=10:0:6
dnl library file name for FIPS selfcheck
LIBCRYPTSETUP_VERSION_FIPS="libcryptsetup.so.4"
FIPS_MODULE_FILE="/etc/system-fips"

AC_CONFIG_SRCDIR(src/cryptsetup.c)
AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_HEADERS([config.h:config.h.in])

# We do not want to run test in parallel. Really.
# http://lists.gnu.org/archive/html/automake/2013-01/msg00060.html

# For old automake use this
#AM_INIT_AUTOMAKE(dist-xz)
AM_INIT_AUTOMAKE([dist-xz 1.12 serial-tests])

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

AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h malloc.h inttypes.h sys/ioctl.h sys/mman.h \
	ctype.h unistd.h locale.h byteswap.h endian.h)

AC_CHECK_HEADERS(uuid/uuid.h,,[AC_MSG_ERROR([You need the uuid library.])])
AC_CHECK_HEADER(libdevmapper.h,,[AC_MSG_ERROR([You need the device-mapper library.])])

saved_LIBS=$LIBS
AC_CHECK_LIB(uuid, uuid_clear, ,[AC_MSG_ERROR([You need the uuid library.])])
AC_SUBST(UUID_LIBS, $LIBS)
LIBS=$saved_LIBS

AC_SEARCH_LIBS([clock_gettime],[rt posix4])
AC_CHECK_FUNCS([posix_memalign clock_gettime])

if test "x$enable_largefile" = "xno" ; then
  AC_MSG_ERROR([Building with --disable-largefile is not supported, it can cause data corruption.])
fi

AC_C_CONST
AC_C_BIGENDIAN
AC_TYPE_OFF_T
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO
AC_PROG_GCC_TRADITIONAL

dnl ==========================================================================

AM_GNU_GETTEXT([external],[need-ngettext])
AM_GNU_GETTEXT_VERSION([0.15])

dnl ==========================================================================

saved_LIBS=$LIBS
AC_CHECK_LIB(popt, poptConfigFileToString,,
	[AC_MSG_ERROR([You need popt 1.7 or newer to compile.])])
AC_SUBST(POPT_LIBS, $LIBS)
LIBS=$saved_LIBS

dnl ==========================================================================
dnl FIPS extensions
AC_ARG_ENABLE([fips], AS_HELP_STRING([--enable-fips],[enable FIPS mode restrictions]),
[with_fips=$enableval],
[with_fips=no])

if test "x$with_fips" = "xyes"; then
	AC_DEFINE(ENABLE_FIPS, 1, [Enable FIPS mode restrictions])
	AC_DEFINE_UNQUOTED(LIBCRYPTSETUP_VERSION_FIPS, ["$LIBCRYPTSETUP_VERSION_FIPS"],
		[library file name for FIPS selfcheck])
	AC_DEFINE_UNQUOTED(FIPS_MODULE_FILE, ["$FIPS_MODULE_FILE"],
		[file checked to determine if running in FIPS mode])

	if test "x$enable_static" = "xyes" -o "x$enable_static_cryptsetup" = "xyes" ; then
		AC_MSG_ERROR([Static build is not compatible with FIPS.])
	fi

	saved_LIBS=$LIBS
	AC_CHECK_LIB(fipscheck, FIPSCHECK_verify, ,[AC_MSG_ERROR([You need the fipscheck library.])])
	AC_SUBST(FIPSCHECK_LIBS, $LIBS)
	LIBS=$saved_LIBS

fi

AC_DEFUN([NO_FIPS], [
	if test "x$with_fips" = "xyes"; then
		AC_MSG_ERROR([This option is not compatible with FIPS.])
	fi
])

dnl ==========================================================================
dnl pwquality library (cryptsetup CLI only)
AC_ARG_ENABLE([pwquality], AS_HELP_STRING([--enable-pwquality],[enable password quality checking]),
[with_pwquality=$enableval],
[with_pwquality=no])

if test "x$with_pwquality" = "xyes"; then
	AC_DEFINE(ENABLE_PWQUALITY, 1, [Enable password quality checking])
	PKG_CHECK_MODULES([PWQUALITY], [pwquality >= 1.0.0],,
		AC_MSG_ERROR([You need pwquality library.]))

	dnl FIXME: this is really hack for now
	PWQUALITY_STATIC_LIBS="$PWQUALITY_LIBS -lcrack -lz"
fi

dnl ==========================================================================
dnl Crypto backend functions

AC_DEFUN([CONFIGURE_GCRYPT], [
	if test "x$with_fips" = "xyes"; then
		GCRYPT_REQ_VERSION=1.4.5
	else
		GCRYPT_REQ_VERSION=1.1.42
	fi
	dnl Check if we can use gcrypt PBKDF2 (1.6.0 supports empty password)
	AC_ARG_ENABLE([gcrypt-pbkdf2], AS_HELP_STRING([--enable-gcrypt-pbkdf2],[force enable internal gcrypt PBKDF2]),
		if test "x$enableval" = "xyes"; then
			[use_internal_pbkdf2=0]
		else
			[use_internal_pbkdf2=1]
		fi,
		[AM_PATH_LIBGCRYPT([1.6.1], [use_internal_pbkdf2=0], [use_internal_pbkdf2=1])])
	AM_PATH_LIBGCRYPT($GCRYPT_REQ_VERSION,,[AC_MSG_ERROR([You need the gcrypt library.])])

	if test x$enable_static_cryptsetup = xyes; then
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

	if test x$enable_static_cryptsetup = xyes; then
		saved_PKG_CONFIG=$PKG_CONFIG
		PKG_CONFIG="$PKG_CONFIG --static"
		PKG_CHECK_MODULES([OPENSSL_STATIC], [openssl])
		CRYPTO_STATIC_LIBS=$OPENSSL_STATIC_LIBS
		PKG_CONFIG=$saved_PKG_CONFIG
	fi
	NO_FIPS([])
])

AC_DEFUN([CONFIGURE_NSS], [
	if test x$enable_static_cryptsetup = xyes; then
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
	AS_HELP_STRING([--enable-static-cryptsetup],
	[enable build of static cryptsetup binary]))
if test x$enable_static_cryptsetup = xyes; then
	if test x$enable_static = xno; then
		AC_MSG_WARN([Requested static cryptsetup build, enabling static library.])
		enable_static=yes
	fi
fi
AM_CONDITIONAL(STATIC_TOOLS, test x$enable_static_cryptsetup = xyes)

AC_ARG_ENABLE(veritysetup,
	AS_HELP_STRING([--disable-veritysetup],
	[disable veritysetup support]),[], [enable_veritysetup=yes])
AM_CONDITIONAL(VERITYSETUP, test x$enable_veritysetup = xyes)

AC_ARG_ENABLE([cryptsetup-reencrypt],
	AS_HELP_STRING([--enable-cryptsetup-reencrypt],
	[enable cryptsetup-reencrypt tool]))
AM_CONDITIONAL(REENCRYPT, test x$enable_cryptsetup_reencrypt = xyes)

AC_ARG_ENABLE(selinux,
	AS_HELP_STRING([--disable-selinux],
	[disable selinux support [default=auto]]),[], [])

AC_ARG_ENABLE([udev],
	AS_HELP_STRING([--disable-udev],
	[disable udev support]),[], enable_udev=yes)

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
AC_CHECK_DECLS([DM_UDEV_DISABLE_DISK_RULES_FLAG], [have_cookie=yes], [have_cookie=no], [#include <libdevmapper.h>])
if test "x$enable_udev" = xyes; then
	if test "x$have_cookie" = xno; then
		AC_MSG_WARN([The device-mapper library on your system has no udev support, udev support disabled.])
	else
		AC_DEFINE(USE_UDEV, 1, [Try to use udev synchronisation?])
	fi
fi
LIBS=$saved_LIBS

dnl Crypto backend configuration.
AC_ARG_WITH([crypto_backend],
	AS_HELP_STRING([--with-crypto_backend=BACKEND], [crypto backend (gcrypt/openssl/nss/kernel/nettle) [gcrypt]]),
	[], with_crypto_backend=gcrypt
)

dnl Kernel crypto API backend needed for benchmark and tcrypt
AC_ARG_ENABLE([kernel_crypto], AS_HELP_STRING([--disable-kernel_crypto],
	[disable kernel userspace crypto (no benchmark and tcrypt)]),
	[with_kernel_crypto=$enableval],
	[with_kernel_crypto=yes])

if test "x$with_kernel_crypto" = "xyes"; then
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
AM_CONDITIONAL(CRYPTO_BACKEND_GCRYPT,  test $with_crypto_backend = gcrypt)
AM_CONDITIONAL(CRYPTO_BACKEND_OPENSSL, test $with_crypto_backend = openssl)
AM_CONDITIONAL(CRYPTO_BACKEND_NSS,     test $with_crypto_backend = nss)
AM_CONDITIONAL(CRYPTO_BACKEND_KERNEL,  test $with_crypto_backend = kernel)
AM_CONDITIONAL(CRYPTO_BACKEND_NETTLE,  test $with_crypto_backend = nettle)

AM_CONDITIONAL(CRYPTO_INTERNAL_PBKDF2, test $use_internal_pbkdf2 = 1)
AC_DEFINE_UNQUOTED(USE_INTERNAL_PBKDF2, [$use_internal_pbkdf2], [Use internal PBKDF2])

dnl Magic for cryptsetup.static build.
if test x$enable_static_cryptsetup = xyes; then
	saved_PKG_CONFIG=$PKG_CONFIG
	PKG_CONFIG="$PKG_CONFIG --static"

	LIBS="$saved_LIBS -static"
	AC_CHECK_LIB(popt, poptGetContext,,
		AC_MSG_ERROR([Cannot find static popt library.]))

	dnl Try to detect needed device-mapper static libraries, try pkg-config first.
	LIBS="$saved_LIBS -static"
	PKG_CHECK_MODULES([DEVMAPPER_STATIC], [devmapper >= 1.02.27],,[
		DEVMAPPER_STATIC_LIBS=$DEVMAPPER_LIBS
		if test "x$enable_selinux" != xno; then
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

AC_SUBST([DEVMAPPER_LIBS])
AC_SUBST([DEVMAPPER_STATIC_LIBS])

AC_SUBST([PWQUALITY_LIBS])
AC_SUBST([PWQUALITY_STATIC_LIBS])

AC_SUBST([CRYPTO_CFLAGS])
AC_SUBST([CRYPTO_LIBS])
AC_SUBST([CRYPTO_STATIC_LIBS])

AC_SUBST([LIBCRYPTSETUP_VERSION])
AC_SUBST([LIBCRYPTSETUP_VERSION_INFO])
AC_SUBST([LIBCRYPTSETUP_VERSION_FIPS])
AC_SUBST([FIPS_MODULE_FILE])

dnl ==========================================================================
AC_ARG_ENABLE([dev-random], AS_HELP_STRING([--enable-dev-random],
[use blocking /dev/random by default for key generator (otherwise use /dev/urandom)]),
[default_rng=/dev/random], [default_rng=/dev/urandom])
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

dnl ==========================================================================
dnl Python bindings
AC_ARG_ENABLE([python], AS_HELP_STRING([--enable-python],[enable Python bindings]),
[with_python=$enableval],
[with_python=no])

AC_ARG_WITH([python_version],
	AS_HELP_STRING([--with-python_version=VERSION], [required Python version [2.6]]),
	[PYTHON_VERSION=$withval], [PYTHON_VERSION=2.6])

if test "x$with_python" = "xyes"; then
	AM_PATH_PYTHON([$PYTHON_VERSION])

	if ! test -x "$PYTHON-config" ; then
            AC_MSG_ERROR([Cannot find python development packages to build bindings])
	fi

	PYTHON_INCLUDES=$($PYTHON-config --includes)
	AC_SUBST(PYTHON_INCLUDES)

	PYTHON_LIBS=$($PYTHON-config --libs)
	AC_SUBST(PYTHON_LIBS)
fi
AM_CONDITIONAL([PYTHON_CRYPTSETUP], [test "x$with_python" = "xyes"])

dnl ==========================================================================
CS_STR_WITH([plain-hash],   [password hashing function for plain mode], [ripemd160])
CS_STR_WITH([plain-cipher], [cipher for plain mode], [aes])
CS_STR_WITH([plain-mode],   [cipher mode for plain mode], [cbc-essiv:sha256])
CS_NUM_WITH([plain-keybits],[key length in bits for plain mode], [256])

CS_STR_WITH([luks1-hash],   [hash function for LUKS1 header], [sha1])
CS_STR_WITH([luks1-cipher], [cipher for LUKS1], [aes])
CS_STR_WITH([luks1-mode],   [cipher mode for LUKS1], [xts-plain64])
CS_NUM_WITH([luks1-keybits],[key length in bits for LUKS1], [256])
CS_NUM_WITH([luks1-iter-time],[PBKDF2 iteration time for LUKS1 (in ms)], [1000])

CS_STR_WITH([loopaes-cipher], [cipher for loop-AES mode], [aes])
CS_NUM_WITH([loopaes-keybits],[key length in bits for loop-AES mode], [256])

CS_NUM_WITH([keyfile-size-maxkb],[maximum keyfile size (in KiB)], [8192])
CS_NUM_WITH([passphrase-size-max],[maximum keyfile size (in characters)], [512])

CS_STR_WITH([verity-hash],       [hash function for verity mode], [sha256])
CS_NUM_WITH([verity-data-block], [data block size for verity mode], [4096])
CS_NUM_WITH([verity-hash-block], [hash block size for verity mode], [4096])
CS_NUM_WITH([verity-salt-size],  [salt size for verity mode], [32])

dnl ==========================================================================

AC_CONFIG_FILES([ Makefile
lib/Makefile
lib/libcryptsetup.pc
lib/crypto_backend/Makefile
lib/luks1/Makefile
lib/loopaes/Makefile
lib/verity/Makefile
lib/tcrypt/Makefile
src/Makefile
po/Makefile.in
man/Makefile
tests/Makefile
python/Makefile
])
AC_OUTPUT
