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

ENABLED_FUZZERS=${ENABLED_FUZZERS:-crypt2_load_fuzz crypt2_load_ondisk_fuzz crypt2_load_proto_plain_json_fuzz}

mkdir -p $SRC
mkdir -p $OUT
mkdir -p $DEPS_PATH
cd $SRC

echo "Installing dependencies"
LIBFUZZER_PATCH="$XPWD/unpoison-mutated-buffers-from-libfuzzer.patch"
in_oss_fuzz && LIBFUZZER_PATCH="$XPWD/cryptsetup/tests/fuzz/unpoison-mutated-buffers-from-libfuzzer.patch"

in_oss_fuzz && apt-get update && apt-get install -y \
    make autoconf automake autopoint libtool pkg-config \
    sharutils gettext expect keyutils ninja-build \
    bison flex

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

# FIXME: temporary fix until libprotobuf stops shuffling C++ requirements
# [ ! -d libprotobuf-mutator ] && git clone --depth 1 https://github.com/google/libprotobuf-mutator.git \
[ ! -d libprotobuf-mutator ] && git clone -q --depth 1 --branch v1.1 -c advice.detachedHead=false \
    https://github.com/google/libprotobuf-mutator.git &&
    [ "$SANITIZER" == "memory" ] && ( cd libprotobuf-mutator; patch -p1 < $LIBFUZZER_PATCH )
last_commit libprotobuf-mutator

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

cd libprotobuf-mutator
mkdir -p build
rm -fr build/*
cd build
cmake .. -GNinja \
    -DCMAKE_INSTALL_PREFIX="$DEPS_PATH" \
    -DPKG_CONFIG_PATH="$PKG_CONFIG_PATH" \
    -DLIB_PROTO_MUTATOR_TESTING=OFF \
    -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON
ninja
ninja install
cd external.protobuf;
cp -Rf bin lib include "$DEPS_PATH";
cd ../../..

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
    cp $SRC/cryptsetup_fuzzing/${fuzzer}_seed_corpus.zip $OUT

    # optionally copy the dictionary if it exists
    if [ -e tests/fuzz/${fuzzer}.dict ]; then
        cp tests/fuzz/${fuzzer}.dict $OUT
    fi
done

cd $XPWD
