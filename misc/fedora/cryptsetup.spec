# Simplified version of RPM spec for Fedora

Summary: Utility for setting up encrypted disks
Name: cryptsetup
Version: 2.8.1
Release: 1%{?dist}
License: GPL-2.0-or-later WITH cryptsetup-OpenSSL-exception AND LGPL-2.1-or-later WITH cryptsetup-OpenSSL-exception
URL: https://gitlab.com/cryptsetup/cryptsetup
BuildRequires: autoconf, automake, libtool, gettext-devel,
BuildRequires: openssl-devel, popt-devel, device-mapper-devel
BuildRequires: libuuid-devel, gcc, json-c-devel
BuildRequires: libpwquality-devel, libblkid-devel
BuildRequires: make libssh-devel
BuildRequires: asciidoctor
Requires: cryptsetup-libs = %{version}-%{release}
Requires: libpwquality >= 1.2.0
Obsoletes: %{name}-reencrypt <= %{version}
Provides: %{name}-reencrypt = %{version}

%global upstream_version %{version_no_tilde}
Source0: https://cdn.kernel.org/pub/linux/utils/cryptsetup/v2.8/cryptsetup-%{upstream_version}.tar.xz

%description
The cryptsetup package contains a utility for setting up
disk encryption using dm-crypt kernel module.

%package devel
Requires: %{name}-libs%{?_isa} = %{version}-%{release}
Requires: pkgconfig
Summary: Headers and libraries for using encrypted file systems

%description devel
The cryptsetup-devel package contains libraries and header files
used for writing code that makes use of disk encryption.

%package libs
Summary: Cryptsetup shared library

%description libs
This package contains the cryptsetup shared library, libcryptsetup.

%package ssh-token
Summary: Cryptsetup LUKS2 SSH token
Requires: cryptsetup-libs = %{version}-%{release}

%description ssh-token
This package contains the LUKS2 SSH token.

%package -n veritysetup
Summary: A utility for setting up dm-verity volumes
Requires: cryptsetup-libs = %{version}-%{release}

%description -n veritysetup
The veritysetup package contains a utility for setting up
disk verification using dm-verity kernel module.

%package -n integritysetup
Summary: A utility for setting up dm-integrity volumes
Requires: cryptsetup-libs = %{version}-%{release}

%description -n integritysetup
The integritysetup package contains a utility for setting up
disk integrity protection using dm-integrity kernel module.

%prep
%autosetup -n cryptsetup-%{upstream_version} -p 1

%build
# force regeneration of manual pages from AsciiDoc
rm -f man/*.8

./autogen.sh
%configure --enable-fips --enable-pwquality --enable-asciidoc
%make_build

%install
%make_install
rm -rf %{buildroot}%{_libdir}/*.la
rm -rf %{buildroot}%{_libdir}/%{name}/*.la

%find_lang cryptsetup

%ldconfig_scriptlets -n cryptsetup-libs

%files
%license COPYING
%doc AUTHORS FAQ.md docs/*ReleaseNotes
%{_mandir}/man8/cryptsetup.8.gz
%{_mandir}/man8/cryptsetup-*.8.gz
%{_sbindir}/cryptsetup

%files -n veritysetup
%license COPYING
%{_mandir}/man8/veritysetup.8.gz
%{_sbindir}/veritysetup

%files -n integritysetup
%license COPYING
%{_mandir}/man8/integritysetup.8.gz
%{_sbindir}/integritysetup

%files devel
%doc docs/examples/*
%{_includedir}/libcryptsetup.h
%{_libdir}/libcryptsetup.so
%{_libdir}/pkgconfig/libcryptsetup.pc

%files libs -f cryptsetup.lang
%license COPYING
%{_libdir}/libcryptsetup.so.*
%dir %{_libdir}/%{name}/
%{_tmpfilesdir}/cryptsetup.conf
%ghost %attr(700, -, -) %dir /run/cryptsetup

%files ssh-token
%license COPYING
%{_libdir}/%{name}/libcryptsetup-token-ssh.so
%{_mandir}/man8/cryptsetup-ssh.8.gz
%{_sbindir}/cryptsetup-ssh

%changelog
