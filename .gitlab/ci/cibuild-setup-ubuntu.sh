#!/bin/bash

set -ex

PACKAGES=(
	git make autoconf automake autopoint pkg-config libtool libtool-bin
	gettext libssl-dev libdevmapper-dev libpopt-dev uuid-dev libsepol-dev
	libjson-c-dev libssh-dev libblkid-dev tar libargon2-0-dev libpwquality-dev
	sharutils dmsetup jq xxd expect keyutils netcat passwd openssh-client sshpass
	asciidoctor
)

COMPILER="${COMPILER:?}"
COMPILER_VERSION="${COMPILER_VERSION:?}"

grep -E '^deb' /etc/apt/sources.list > /etc/apt/sources.list~
sed -Ei 's/^deb /deb-src /' /etc/apt/sources.list~
cat /etc/apt/sources.list~ >> /etc/apt/sources.list

apt-get -y update --fix-missing
DEBIAN_FRONTEND=noninteractive apt-get -yq install software-properties-common wget lsb-release
RELEASE="$(lsb_release -cs)"

if [[ $COMPILER == "gcc" ]]; then
	# Latest gcc stack deb packages provided by
	# https://launchpad.net/~ubuntu-toolchain-r/+archive/ubuntu/test
	add-apt-repository -y ppa:ubuntu-toolchain-r/test
	PACKAGES+=(gcc-$COMPILER_VERSION)
elif [[ $COMPILER == "clang" ]]; then
	wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
	add-apt-repository "deb http://apt.llvm.org/${RELEASE}/   llvm-toolchain-${RELEASE}-${COMPILER_VERSION} main"

	# scan-build
	PACKAGES+=(clang-tools-$COMPILER_VERSION clang-$COMPILER_VERSION lldb-$COMPILER_VERSION lld-$COMPILER_VERSION clangd-$COMPILER_VERSION)
	PACKAGES+=(perl)
else
	exit 1
fi

apt-get -y update --fix-missing
DEBIAN_FRONTEND=noninteractive apt-get -yq install "${PACKAGES[@]}"
apt-get -y build-dep cryptsetup

echo "====================== VERSIONS ==================="
if [[ $COMPILER == "clang" ]]; then
	echo "Using scan-build${COMPILER_VERSION:+-$COMPILER_VERSION}"
fi

${COMPILER}-$COMPILER_VERSION -v
echo "====================== END VERSIONS ==================="
