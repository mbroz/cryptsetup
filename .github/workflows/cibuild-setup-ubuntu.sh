#!/bin/bash

set -ex

PACKAGES=(
	git make autoconf automake autopoint pkg-config libtool libtool-bin
	gettext libssl-dev libdevmapper-dev libpopt-dev uuid-dev libsepol-dev
	libjson-c-dev libssh-dev libblkid-dev tar libargon2-dev libpwquality-dev
	sharutils dmsetup jq xxd expect keyutils netcat-openbsd passwd openssh-client
	sshpass asciidoctor meson ninja-build
)

COMPILER="${COMPILER:?}"
COMPILER_VERSION="${COMPILER_VERSION:?}"
RELEASE="$(lsb_release -cs)"

bash -c "echo 'deb-src http://archive.ubuntu.com/ubuntu/ $RELEASE main restricted universe multiverse' >>/etc/apt/sources.list"

# Latest gcc stack deb packages provided by
# https://launchpad.net/~ubuntu-toolchain-r/+archive/ubuntu/test
add-apt-repository -y ppa:ubuntu-toolchain-r/test
PACKAGES+=(gcc-$COMPILER_VERSION)

# scsi_debug, gost crypto
PACKAGES+=(dkms linux-headers-$(uname -r) linux-modules-extra-$(uname -r) gost-crypto-dkms)

apt-get -y update --fix-missing
apt-get -y install "${PACKAGES[@]}"
apt-get -y build-dep cryptsetup
