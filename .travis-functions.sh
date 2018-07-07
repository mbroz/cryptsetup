#!/bin/bash
#
# .travis-functions.sh:
#   - helper functions to be sourced from .travis.yml
#   - designed to respect travis' environment but testing locally is possible
#   - modified copy from util-linux project
#

if [ ! -f "configure.ac" ]; then
	echo ".travis-functions.sh must be sourced from source dir" >&2
	return 1 || exit 1
fi

## some config settings
# travis docs say we get 1.5 CPUs
MAKE="make -j2"
DUMP_CONFIG_LOG="short"
export TS_OPT_parsable="yes"

function configure_travis
{
	./configure "$@"
	err=$?
	if [ "$DUMP_CONFIG_LOG" = "short" ]; then
		grep -B1 -A10000 "^## Output variables" config.log | grep -v "_FALSE="
	elif [ "$DUMP_CONFIG_LOG" = "full" ]; then
		cat config.log
	fi
	return $err
}

function check_nonroot
{
	local cfg_opts="$1"

	[ -z "$cfg_opts" ] && return

	configure_travis \
		--enable-python \
		--enable-cryptsetup-reencrypt \
		--enable-internal-sse-argon2 \
		"$cfg_opts" \
		|| return

	$MAKE || return

	sudo modprobe dm-crypt
	sudo modprobe dm-verity
	sudo modprobe dm-integrity
	uname -a
	sudo dmsetup version
	sudo dmsetup targets

	make check
}

function check_root
{
	local cfg_opts="$1"

	[ -z "$cfg_opts" ] && return

    configure_travis \
		--enable-python \
		--enable-cryptsetup-reencrypt \
		--enable-internal-sse-argon2 \
		"$cfg_opts" \
		|| return

	$MAKE || return

	sudo modprobe dm-crypt
	sudo modprobe dm-verity
	sudo modprobe dm-integrity
	uname -a
	sudo dmsetup version
	sudo dmsetup targets

	# FIXME: we should use -E option here
	sudo make check
}

function check_nonroot_compile_only
{
	local cfg_opts="$1"

	[ -z "$cfg_opts" ] && return

	configure_travis \
		--enable-python \
		--enable-cryptsetup-reencrypt \
		--enable-internal-sse-argon2 \
		"$cfg_opts" \
		|| return

	$MAKE
}

function travis_install_script
{
	# install some packages from Ubuntu's default sources
	sudo apt-get -qq update
	sudo apt-get install -qq >/dev/null \
		python-dev \
		sharutils \
		libgcrypt20-dev \
		libssl-dev \
		libdevmapper-dev \
		libpopt-dev \
		uuid-dev \
		libsepol1-dev \
		libtool \
		dmsetup \
		autoconf \
		automake \
		pkg-config \
		autopoint \
		gettext \
		expect \
		keyutils \
		libjson-c-dev \
		libblkid-dev \
		|| return
}

function travis_before_script
{
	set -o xtrace

	./autogen.sh
	ret=$?

	set +o xtrace
	return $ret
}

function travis_script
{
	local ret
	set -o xtrace

	case "$MAKE_CHECK" in
	gcrypt)
		check_nonroot "--with-crypto_backend=gcrypt" && \
		check_root "--with-crypto_backend=gcrypt"
		;;
	gcrypt_compile)
		check_nonroot_compile_only "--with-crypto_backend=gcrypt"
		;;
	openssl)
		check_nonroot "--with-crypto_backend=openssl" && \
		check_root "--with-crypto_backend=openssl"
		;;
	openssl_compile)
		check_nonroot_compile_only "--with-crypto_backend=openssl"
		;;
	*)
		echo "error, check environment (travis.yml)" >&2
		false
		;;
	esac

	ret=$?
	set +o xtrace
	return $ret
}

function travis_after_script
{
	return 0
}
