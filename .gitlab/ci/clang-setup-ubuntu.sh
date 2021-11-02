#!/bin/bash

set -ex

PACKAGES=(
	git make autoconf automake autopoint pkg-config libtool libtool-bin
	gettext libssl-dev libdevmapper-dev libpopt-dev uuid-dev libsepol1-dev
	libjson-c-dev libssh-dev libblkid-dev tar libargon2-0-dev libpwquality-dev
	sharutils dmsetup jq xxd expect keyutils netcat passwd openssh-client sshpass
)

COMPILER="${COMPILER:?}"
COMPILER_VERSION="${COMPILER_VERSION:?}"

grep -E '^deb' /etc/apt/sources.list > /etc/apt/sources.list~
sed -Ei 's/^deb /deb-src /' /etc/apt/sources.list~
cat /etc/apt/sources.list~ >> /etc/apt/sources.list
#bash -c "echo 'deb-src http://archive.ubuntu.com/ubuntu/ $RELEASE main restricted universe multiverse' >>/etc/apt/sources.list"

apt-get -y update --fix-missing
DEBIAN_FRONTEND=noninteractive apt-get -yq install software-properties-common

# Latest gcc stack deb packages provided by
# https://launchpad.net/~ubuntu-toolchain-r/+archive/ubuntu/test
add-apt-repository -y ppa:ubuntu-toolchain-r/test
PACKAGES+=(gcc-$COMPILER_VERSION)

DEBIAN_FRONTEND=noninteractive apt-get -yq install "${PACKAGES[@]}"
apt-get -y build-dep cryptsetup
