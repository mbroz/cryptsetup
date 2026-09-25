#!/usr/bin/env bash

in_oss_fuzz()
{
    test -n "$FUZZING_ENGINE"
}

last_commit()
{
    echo "$(git -C "$1" log --format="%h %s" -n 1) ($1)"
}

echo "Running cryptsetup OSS-Fuzz build script for ${SANITIZER:-address} sanitizer."
#env ; set -x
set -e
XPWD="$(pwd)"

export LC_CTYPE=C.UTF-8

export SRC="${SRC:-$XPWD/build}"
export OUT="${OUT:-$XPWD/out}"
export DEPS_PATH=$SRC/static_lib_deps

export PKG_CONFIG_PATH="$DEPS_PATH"/lib/pkgconfig

export CC=${CC:-clang}
export CXX=${CXX:-clang++}
export LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}"

SANITIZER="${SANITIZER:-address -fsanitize-address-use-after-scope}"
flags="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=$SANITIZER -fsanitize=fuzzer-no-link"

export CFLAGS="${CFLAGS:-$flags} -I$DEPS_PATH/include"
export CXXFLAGS="${CXXFLAGS:-$flags} -I$DEPS_PATH/include"
export LDFLAGS="${LDFLAGS-} -L$DEPS_PATH/lib"

ENABLED_FUZZERS=${ENABLED_FUZZERS:-crypt2_load_fuzz crypt2_load_ondisk_fuzz crypt_load_misc_fuzz crypt2_meta_fuzz}

mkdir -p $SRC
mkdir -p $OUT
mkdir -p $DEPS_PATH
cd $SRC

echo "Installing dependencies"

in_oss_fuzz && apt-get update && apt-get install -y \
    make autoconf automake autopoint libtool pkg-config \
    sharutils gettext expect keyutils bison flex

echo "Cloning git repositories"
# FIXME: temporary use branch master instead of develop
[ ! -d zlib ] && git clone -q --depth 1 --branch master https://github.com/madler/zlib.git
last_commit zlib

# Upstream repo has disabled cloning https://git.tukaani.org/xz.git
[ ! -d xz ] && git clone -q --depth 1 https://github.com/tukaani-project/xz
last_commit xz

[ ! -d json-c ] && git clone -q --depth 1 https://github.com/json-c/json-c.git
last_commit json-c

[ ! -d lvm2 ] && git clone -q --depth 1 https://gitlab.com/lvmteam/lvm2
last_commit lvm2

[ ! -d popt ] && git clone -q --depth 1 https://github.com/rpm-software-management/popt.git
last_commit popt

[ ! -d openssl ] && git clone -q --depth 1 https://github.com/openssl/openssl
last_commit openssl

[ ! -d util-linux ] && git clone -q --depth 1 https://github.com/util-linux/util-linux
last_commit util-linux

[ ! -d cryptsetup_fuzzing ] && git clone -q --depth 1 https://gitlab.com/cryptsetup/cryptsetup_fuzzing.git

echo "Building libraries from git"
cd openssl
./Configure --prefix="$DEPS_PATH" --libdir=lib no-shared no-module no-asm
make build_generated
make -j libcrypto.a
make install_dev
cd ..

cd util-linux
./autogen.sh
./configure --prefix="$DEPS_PATH" --enable-static --disable-shared -disable-all-programs --enable-libuuid --enable-libblkid
make -j
make install
cd ..

cd zlib
./configure --prefix="$DEPS_PATH" --static
make -j
make install
cd ..

cd xz
./autogen.sh --no-po4a --no-doxygen
./configure --prefix="$DEPS_PATH" --enable-static --disable-shared --disable-ifunc --disable-sandbox
make -j
make install
cd ..

cd json-c
mkdir -p build
rm -fr build/*
cd build
cmake .. -DCMAKE_INSTALL_PREFIX="$DEPS_PATH" -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON
make -j
make install
cd ../..

cd lvm2
./configure --prefix="$DEPS_PATH" --enable-static_link --disable-udev_sync --enable-pkgconfig --disable-selinux
make -j libdm.device-mapper
make -C libdm install_static install_pkgconfig install_include
cd ..

cd popt
# --no-undefined is incompatible with sanitizers
sed -i -e 's/-Wl,--no-undefined //' src/CMakeLists.txt
# force static build of popt
sed -i 's/add_library(popt SHARED/add_library(popt STATIC/' src/CMakeLists.txt
mkdir -p build
rm -fr build/*
cd build
cmake .. -DCMAKE_INSTALL_PREFIX="$DEPS_PATH" -DBUILD_SHARED_LIBS=OFF
make -j
make install
cd ../..

echo "Building cryptsetup fuzzers"
if in_oss_fuzz; then
    mkdir -p cryptsetup/tests/fuzz/build
    ln -s ../../../../static_lib_deps cryptsetup/tests/fuzz/build/static_lib_deps
    cd cryptsetup
else
    cd ../../..
fi
./autogen.sh
./configure --enable-static --disable-asciidoc --disable-ssh-token --disable-udev --disable-selinux --with-crypto_backend=openssl --disable-shared --enable-fuzz-targets
make clean
make -j fuzz-targets

echo "Installing fuzzers"
for fuzzer in $ENABLED_FUZZERS; do
    cp tests/fuzz/$fuzzer $OUT

    # a target keeps its own corpus in the cryptsetup_fuzzing repository; a new
    # target may not have one there yet
    if [ -e $SRC/cryptsetup_fuzzing/${fuzzer}_seed_corpus.zip ]; then
        cp $SRC/cryptsetup_fuzzing/${fuzzer}_seed_corpus.zip $OUT
    fi

    # optionally copy the dictionary if it exists
    if [ -e tests/fuzz/${fuzzer}.dict ]; then
        cp tests/fuzz/${fuzzer}.dict $OUT
    fi
done

# crypt2_meta_fuzz only reaches the metadata API when crypt_load() succeeds, so
# it is seeded from the LUKS2 images the test suite already ships rather than
# from another target's corpus. Each image is cut to its first megabyte, which
# holds the binary header and the JSON area of the default metadata sizes.
if [ ! -e $SRC/cryptsetup_fuzzing/crypt2_meta_fuzz_seed_corpus.zip ]; then
    meta_corpus="$PWD/tests/fuzz/meta_corpus"
    rm -rf "$meta_corpus"
    mkdir -p "$meta_corpus"
    for img in tests/luks2_valid_hdr.img.xz tests/luks2_keyslot_unassigned.img.xz \
               tests/luks2_invalid_cipher.img.xz tests/compatimage2.img.xz; do
        [ -e "$img" ] || continue
        xz -dc "$img" 2>/dev/null | head -c 1048576 > "$meta_corpus/$(basename $img .img.xz).bin"
    done
    for arch in tests/luks2_header_requirements.tar.xz tests/luks2_mda_images.tar.xz; do
        [ -e "$arch" ] || continue
        tar -xJf "$arch" -C "$meta_corpus" 2>/dev/null || true
    done
    find "$meta_corpus" -type f -size +1M -exec truncate -s 1M {} +
    # zip appends to an existing archive, so start from nothing
    rm -f $OUT/crypt2_meta_fuzz_seed_corpus.zip
    zip -j -q $OUT/crypt2_meta_fuzz_seed_corpus.zip "$meta_corpus"/* 2>/dev/null || true
    rm -rf "$meta_corpus"
fi

cd $XPWD
