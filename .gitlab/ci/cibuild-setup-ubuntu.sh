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

apt-get -y update --fix-missing
DEBIAN_FRONTEND=noninteractive apt-get -yq install software-properties-common wget lsb-release
if [[ $COMPILER == "gcc" ]]; then
  # Latest gcc stack deb packages provided by
  # https://launchpad.net/~ubuntu-toolchain-r/+archive/ubuntu/test
  add-apt-repository -y ppa:ubuntu-toolchain-r/test
elif [[ $COMPILER == "clang" ]]; then
  .gitlab/ci/llvm.sh $COMPILER_VERSION
  # scan-build
  PACKAGES+=(clang-tools-$COMPILER_VERSION)
  PACKAGES+=(perl)
else
  exit 1
fi

PACKAGES+=(${COMPILER}-$COMPILER_VERSION)

DEBIAN_FRONTEND=noninteractive apt-get -yq install "${PACKAGES[@]}"
apt-get -y build-dep cryptsetup

echo "====================== VERSIONS ==================="
if [[ $COMPILER == "clang" ]]; then
  scan-build${COMPILER_VERSION:+-$COMPILER_VERSION} --help
fi

${COMPILER}-$COMPILER_VERSION -v
echo "====================== END VERSIONS ==================="
