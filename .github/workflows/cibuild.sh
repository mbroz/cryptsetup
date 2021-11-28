#!/bin/bash

PHASES=(${@:-CONFIGURE MAKE CHECK})
COMPILER="${COMPILER:?}"
COMPILER_VERSION="${COMPILER_VERSION}"
CFLAGS=(-O1 -g)
CXXFLAGS=(-O1 -g)

CC="gcc${COMPILER_VERSION:+-$COMPILER_VERSION}"
CXX="g++${COMPILER_VERSION:+-$COMPILER_VERSION}"

set -ex

for phase in "${PHASES[@]}"; do
	case $phase in
	CONFIGURE)
		opts=(
			--enable-libargon2
		)

		sudo -E git clean -xdf

		./autogen.sh
		CC="$CC" CXX="$CXX" CFLAGS="${CFLAGS[@]}" CXXFLAGS="${CXXFLAGS[@]}" ./configure "${opts[@]}"
		;;
	MAKE)
		make -j
		make -j -C tests check-programs
		;;
	CHECK)
		make check
		;;

	*)
		echo >&2 "Unknown phase '$phase'"
		exit 1
	esac
done
