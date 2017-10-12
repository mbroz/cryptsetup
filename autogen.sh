#!/bin/sh
# Run this to generate all the initial makefiles, etc.

srcdir=`dirname $0`
PKG_NAME="cryptsetup"

DIE=0

(autopoint --version) < /dev/null > /dev/null 2>&1 || {
  echo
  echo "**Error**: You must have autopoint installed."
  echo "Download the appropriate package for your distribution,"
  echo "or see http://www.gnu.org/software/gettext"
  DIE=1
}

(autoconf --version) < /dev/null > /dev/null 2>&1 || {
  echo
  echo "**Error**: You must have autoconf installed to."
  echo "Download the appropriate package for your distribution,"
  echo "or get the source tarball at ftp://ftp.gnu.org/pub/gnu/"
  DIE=1
}

(grep "^AM_PROG_LIBTOOL" $srcdir/configure.ac >/dev/null) && {
  (libtool --version) < /dev/null > /dev/null 2>&1 || {
    echo
    echo "**Error**: You must have libtool installed."
    echo "Get ftp://ftp.gnu.org/pub/gnu/"
    echo "(or a newer version if it is available)"
    DIE=1
  }
}

(automake --version) < /dev/null > /dev/null 2>&1 || {
  echo
  echo "**Error**: You must have automake installed."
  echo "Get ftp://ftp.gnu.org/pub/gnu/"
  echo "(or a newer version if it is available)"
  DIE=1
  NO_AUTOMAKE=yes
}


# if no automake, don't bother testing for aclocal
test -n "$NO_AUTOMAKE" || (aclocal --version) < /dev/null > /dev/null 2>&1 || {
  echo
  echo "**Error**: Missing aclocal.  The version of automake"
  echo "installed doesn't appear recent enough."
  echo "Get ftp://ftp.gnu.org/pub/gnu/"
  echo "(or a newer version if it is available)"
  DIE=1
}

if test "$DIE" -eq 1; then
  exit 1
fi

echo
echo "Generate build-system by:"
echo "   autopoint:  $(autopoint --version | head -1)"
echo "   aclocal:    $(aclocal --version | head -1)"
echo "   autoconf:   $(autoconf --version | head -1)"
echo "   automake:   $(automake --version | head -1)"
echo "   libtoolize: $(libtoolize --version | head -1)"
echo


set -e
autopoint --force $AP_OPTS
libtoolize --force --copy
aclocal -I m4 $AL_OPTS
autoheader $AH_OPTS
automake --add-missing --copy --gnu $AM_OPTS
autoconf $AC_OPTS

echo
echo "Now type '$srcdir/configure' and 'make' to compile."
echo
