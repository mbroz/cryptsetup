#!/usr/bin/env bash

function in_oss_fuzz()
{
    test -n "$FUZZING_ENGINE"
}

echo "Running cryptsetup OSS-Fuzz build script."
env
set -ex
PWD=$(pwd)

export LC_CTYPE=C.UTF-8

export SRC=${SRC:-$PWD/build}
export OUT="${OUT:-$PWD/out}"
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

in_oss_fuzz && apt-get update && apt-get install -y \
    make autoconf automake autopoint libtool pkg-config \
    sharutils gettext expect keyutils ninja-build \
    bison

[ ! -d zlib ]   && git clone --depth 1 https://github.com/madler/zlib.git
[ ! -d xz ]     && git clone https://git.tukaani.org/xz.git
[ ! -d json-c ] && git clone --depth 1 https://github.com/json-c/json-c.git
[ ! -d lvm2 ]   && git clone --depth 1 https://sourceware.org/git/lvm2.git
[ ! -d popt ]   && git clone --depth 1 https://github.com/rpm-software-management/popt.git
[ ! -d libprotobuf-mutator ] && git clone --depth 1 https://github.com/google/libprotobuf-mutator.git
[ ! -d openssl ]    && git clone --depth 1 https://github.com/openssl/openssl
[ ! -d util-linux ] && git clone --depth 1 https://github.com/util-linux/util-linux
[ ! -d cryptsetup_fuzzing ] && git clone --depth 1 -b multiple_types https://gitlab.com/xflord/cryptsetup_fuzzing.git

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
./autogen.sh --no-po4a
./configure --prefix="$DEPS_PATH" --enable-static --disable-shared
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
# build of dmsetup.static is broken
# make install_device-mapper
cp ./libdm/ioctl/libdevmapper.a "$DEPS_PATH"/lib/
cp ./libdm/libdevmapper.h "$DEPS_PATH"/include/
cp ./libdm/libdevmapper.pc "$PKG_CONFIG_PATH"
cd ..

cd popt
./autogen.sh
./configure --prefix="$DEPS_PATH" --disable-shared --enable-static
make -j
make install
cd ..

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

for fuzzer in $ENABLED_FUZZERS; do
    cp tests/fuzz/$fuzzer $OUT
    if [ -e $SRC/cryptsetup_fuzzing/${fuzzer}_seed_corpus.zip ]; then
      cp $SRC/cryptsetup_fuzzing/${fuzzer}_seed_corpus.zip $OUT
    fi

    # optionally copy the dictionary if it exists
    if [ -e tests/fuzz/${fuzzer}.dict ]; then
        cp tests/fuzz/${fuzzer}.dict $OUT
    fi
done

cd $PWD
