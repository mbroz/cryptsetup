#!/bin/sh
# Run this to generate all the initial makefiles, etc.

srcdir=`dirname $0`
PKG_NAME="cryptsetup"

DIE=0

(autopoint --version) < /dev/null > /dev/null 2>&1 || {
  echo
  echo "**Error**: You must have autopoint installed."
  echo "Download the appropriate package for your distribution."
  DIE=1
}


(msgfmt --version) < /dev/null > /dev/null 2>&1 || {
  echo
  echo "**Warning**: You should have gettext installed."
  echo "Download the appropriate package for your distribution."
  echo "To disable translation, you can also use --disable-nls"
  echo "configure option."
}

(autoconf --version) < /dev/null > /dev/null 2>&1 || {
  echo
  echo "**Error**: You must have autoconf installed."
  echo "Download the appropriate package for your distribution."
  DIE=1
}

(grep "^LT_INIT" $srcdir/configure.ac >/dev/null) && {
  (libtoolize --version) < /dev/null > /dev/null 2>&1 || {
    echo
    echo "**Error**: You must have libtoolize installed."
    echo "Download the appropriate package for your distribution."
    DIE=1
  }
}

(automake --version) < /dev/null > /dev/null 2>&1 || {
  echo
  echo "**Error**: You must have automake installed."
  echo "Download the appropriate package for your distribution."
  DIE=1
  NO_AUTOMAKE=yes
}


# if no automake, don't bother testing for aclocal
test -n "$NO_AUTOMAKE" || (aclocal --version) < /dev/null > /dev/null 2>&1 || {
  echo
  echo "**Error**: Missing aclocal.  The version of automake"
  echo "installed doesn't appear recent enough."
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
automake --force-missing --add-missing --copy --gnu $AM_OPTS
autoconf $AC_OPTS

echo
echo "Now type '$srcdir/configure' and 'make' to compile."
echo
