![LUKS logo](https://gitlab.com/cryptsetup/cryptsetup/wikis/luks-logo.png)

What the ...?
=============
**Cryptsetup** is an open-source utility used to conveniently set up disk encryption based
on the [dm-crypt](https://gitlab.com/cryptsetup/cryptsetup/wikis/DMCrypt) kernel module.

These formats are supported:
  * **plain** volumes,
  * **LUKS** volumes,
  * **loop-AES**,
  * **TrueCrypt** (including **VeraCrypt** extension),
  * **BitLocker**, and
  * **FileVault2**.

The project also includes a **veritysetup** utility used to conveniently setup
[dm-verity](https://gitlab.com/cryptsetup/cryptsetup/wikis/DMVerity)
block integrity checking kernel module and **integritysetup** to setup
[dm-integrity](https://gitlab.com/cryptsetup/cryptsetup/wikis/DMIntegrity)
block integrity kernel module.

LUKS Design
-----------
**LUKS** is the standard for Linux disk encryption. By providing a standard on-disk format,
it does not only facilitate compatibility among distributions, but also provides secure management
of multiple user passwords. LUKS stores all necessary setup information in the partition header,
enabling to transport or migrate data seamlessly.

### Specification and documentation

  * The latest version of the
  [LUKS2 format specification](https://gitlab.com/cryptsetup/LUKS2-docs).
  * The latest version of the
  [LUKS1 format specification](https://www.kernel.org/pub/linux/utils/cryptsetup/LUKS_docs/on-disk-format.pdf).
  * [Project home page](https://gitlab.com/cryptsetup/cryptsetup/).
  * [Frequently asked questions (FAQ)](https://gitlab.com/cryptsetup/cryptsetup/wikis/FrequentlyAskedQuestions)

Download
--------
All release tarballs and release notes are hosted on
[kernel.org](https://www.kernel.org/pub/linux/utils/cryptsetup/).

**The latest stable cryptsetup release version is 2.6.1**
  * [cryptsetup-2.6.1.tar.xz](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.6/cryptsetup-2.6.1.tar.xz)
  * Signature [cryptsetup-2.6.1.tar.sign](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.6/cryptsetup-2.6.1.tar.sign)
    _(You need to decompress file first to check signature.)_
  * [Cryptsetup 2.6.1 Release Notes](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.6/v2.6.1-ReleaseNotes).

Previous versions
 * [Version 2.5.0](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.5/cryptsetup-2.5.0.tar.xz) -
   [Signature](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.5/cryptsetup-2.5.0.tar.sign) -
   [Release Notes](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.5/v2.5.0-ReleaseNotes).
 * [Version 1.7.5](https://www.kernel.org/pub/linux/utils/cryptsetup/v1.7/cryptsetup-1.7.5.tar.xz) -
   [Signature](https://www.kernel.org/pub/linux/utils/cryptsetup/v1.7/cryptsetup-1.7.5.tar.sign) -
   [Release Notes](https://www.kernel.org/pub/linux/utils/cryptsetup/v1.7/v1.7.5-ReleaseNotes).

Source and API documentation
----------------------------
For development version code, please refer to
[source](https://gitlab.com/cryptsetup/cryptsetup/tree/master) page,
mirror on [kernel.org](https://git.kernel.org/cgit/utils/cryptsetup/cryptsetup.git/) or
[GitHub](https://github.com/mbroz/cryptsetup).

For libcryptsetup documentation see
[libcryptsetup API](https://mbroz.fedorapeople.org/libcryptsetup_API/) page.

The libcryptsetup API/ABI changes are tracked in
[compatibility report](https://abi-laboratory.pro/tracker/timeline/cryptsetup/).

NLS PO files are maintained by
[TranslationProject](https://translationproject.org/domain/cryptsetup.html).

Required packages
-----------------
All distributions provide cryptsetup as distro package. If you need to compile cryptsetup yourself,
some packages are required for compilation.
Please always prefer distro specific build tools to manually configuring cryptsetup.

Here is the list of packages needed for the compilation of project for particular distributions:

**For Fedora**:
```
git gcc make autoconf automake gettext-devel pkgconfig openssl-devel popt-devel device-mapper-devel
libuuid-devel json-c-devel libblkid-devel findutils libtool libssh-devel tar

Optionally: libargon2-devel libpwquality-devel
```
To run the internal testsuite (make check) you also need to install
```
sharutils device-mapper jq vim-common expect keyutils netcat shadow-utils openssh-clients openssh sshpass
```

**For Debian and Ubuntu**:
```
git gcc make autoconf automake autopoint pkg-config libtool gettext libssl-dev libdevmapper-dev
libpopt-dev uuid-dev libsepol1-dev libjson-c-dev libssh-dev libblkid-dev tar

Optionally: libargon2-0-dev libpwquality-dev
```
To run the internal testsuite (make check) you also need to install
```
sharutils dmsetup jq xxd expect keyutils netcat passwd openssh-client sshpass
```

Note that the list could change as the distributions evolve.

Compilation
-----------
The cryptsetup project uses **automake** and **autoconf** system to generate all needed files
for compilation. If you check it from the git snapshot, use **./autogen.sh && ./configure && make**
to compile the project. If you use downloaded released **tar.xz** archive, the configure script
is already pre-generated (no need to run **autoconf.sh**).
See **./configure --help** and use **--disable-[feature]** and **--enable-[feature]** options.

For running the test suite that come with the project, type **make check**.
Note that most tests will need root user privileges and run many dangerous storage fail simulations.
Do **not** run tests with root privilege on production systems! Some tests will need scsi_debug
kernel module to be available.

For more details, please refer to [automake](https://www.gnu.org/software/automake/manual/automake.html)
and [autoconf](https://www.gnu.org/savannah-checkouts/gnu/autoconf/manual/autoconf.html) manuals.

Help!
-----
### Documentation
Please read the following documentation before posting questions in the mailing list...
You will be able to ask better questions and better understand the answers.

* [Frequently asked questions (FAQ)](https://gitlab.com/cryptsetup/cryptsetup/wikis/FrequentlyAskedQuestions),
* [LUKS Specifications](#specification-and-documentation), and
* manuals (aka man page, man pages, man-page) 

The FAQ is online and in the source code for the project. The Specifications are referenced above
in this document. The man pages are in source and should be available after installation using
standard man commands, e.g. **man cryptsetup**.

### Mailing List

For cryptsetup and LUKS related questions, please use the cryptsetup mailing list
[cryptsetup@lists.linux.dev](mailto:cryptsetup@lists.linux.dev),
hosted at [kernel.org subspace](https://subspace.kernel.org/lists.linux.dev.html).
To subscribe send an empty mail to
[cryptsetup+subscribe@lists.linux.dev](mailto:cryptsetup+subscribe@lists.linux.dev).

You can also browse and/or search the mailing [list archive](https://lore.kernel.org/cryptsetup/).
News (NNTP), Atom feed and git access to public inbox is available through [lore.kernel.org](https://lore.kernel.org) service.

The former dm-crypt [list archive](https://lore.kernel.org/dm-crypt/) is also available.
