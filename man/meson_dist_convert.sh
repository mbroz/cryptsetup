#!/bin/sh

# generates manpages from AsciiDoc files when building dist tarball
# run asciidoctor in parallel on `nproc` cores

set -e

[ -z "$MESON_DIST_ROOT" ] && echo "This script is meant to be run only from meson while generating dist tarball." && exit 1

if [ $# -lt 3 ]; then
        echo "Usage: $0 <asciidoctor path> <release version> <adocfiles>"
        exit 1
fi

ASCIIDOCTOR="$1"
RELEASE_VERSION="$2"
shift 2

cd $MESON_DIST_ROOT/man
i=1
N=$(nproc)
for adocfile in "$@"
do
    $ASCIIDOCTOR -b manpage --failure-level ERROR -a release-version=$RELEASE_VERSION --base-dir=$MESON_DIST_ROOT $adocfile &
    if [ $(( $i % $N )) -eq 0 ]; then wait; fi
    i=$((i+1))
done
