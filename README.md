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
**LUKS** is the standard for Linux disk encryption. By providing a standardized on-disk format,
it not only facilitate compatibility among distributions, but also enables secure management
of multiple user passwords. LUKS stores all necessary setup information in the partition header,
which enables users to transport or migrate data seamlessly.

### Specification and documentation
  * The latest version of the
  [LUKS2 format specification](https://gitlab.com/cryptsetup/LUKS2-docs).
  * The latest version of the
  [LUKS1 format specification](https://cdn.kernel.org/pub/linux/utils/cryptsetup/LUKS_docs/on-disk-format.pdf).
  * [Project home page](https://gitlab.com/cryptsetup/cryptsetup/).
  * [Frequently asked questions (FAQ)](https://gitlab.com/cryptsetup/cryptsetup/wikis/FrequentlyAskedQuestions)

Download
--------
Release notes and tarballs are available at
[kernel.org](https://cdn.kernel.org/pub/linux/utils/cryptsetup/).

**The latest stable cryptsetup release version is 2.8.1**
  * [cryptsetup-2.8.1.tar.xz](https://cdn.kernel.org/pub/linux/utils/cryptsetup/v2.8/cryptsetup-2.8.1.tar.xz)
  * Signature [cryptsetup-2.8.1.tar.sign](https://cdn.kernel.org/pub/linux/utils/cryptsetup/v2.8/cryptsetup-2.8.1.tar.sign)
    _(You need to decompress file first to check signature.)_
  * [Cryptsetup 2.8.1 Release Notes](https://cdn.kernel.org/pub/linux/utils/cryptsetup/v2.8/v2.8.1-ReleaseNotes).

[Previous versions](https://cdn.kernel.org/pub/linux/utils/cryptsetup)

Source and API documentation
----------------------------
For development version code, please refer to the
[source](https://gitlab.com/cryptsetup/cryptsetup/tree/master) page, with mirrors
at [kernel.org](https://git.kernel.org/cgit/utils/cryptsetup/cryptsetup.git/) and
[GitHub](https://github.com/mbroz/cryptsetup).

For libcryptsetup documentation see
[libcryptsetup API](https://mbroz.fedorapeople.org/libcryptsetup_API/) page.

NLS PO files are maintained by
[TranslationProject](https://translationproject.org/domain/cryptsetup.html).

Required packages
-----------------
All major Linux distributions provide cryptsetup as a bundled package. If you need
to compile cryptsetup yourself, various additional packages are required.
Any distribution-specific build tools are preferred when manually configuring cryptsetup.

Below are the packages needed to build for certain Linux distributions:

**For Fedora**:
```
git gcc make autoconf automake gettext-devel pkgconfig openssl-devel popt-devel device-mapper-devel libuuid-devel json-c-devel libblkid-devel findutils libtool libssh-devel tar rubygem-asciidoctor

Optionally: libargon2-devel libpwquality-devel
```
To run the internal testsuite (make check) you also need to install
```
sharutils device-mapper jq vim-common expect keyutils netcat shadow-utils openssh-clients openssh sshpass
```

**For Debian and Ubuntu**:
```
git gcc make autoconf automake autopoint pkg-config libtool gettext libssl-dev libdevmapper-dev libpopt-dev uuid-dev libsepol-dev libjson-c-dev libssh-dev libblkid-dev tar asciidoctor

Optionally: libargon2-0-dev libpwquality-dev
```
To run the internal testsuite (make check) you also need to install
```
sharutils dmsetup jq xxd expect keyutils netcat-openbsd passwd openssh-client sshpass
```

Note that the list may change as Linux distributions evolve.

Compilation
-----------
The cryptsetup project uses **automake** and **autoconf** system to generate all files needed to build.
When building from a git snapshot,, use **./autogen.sh && ./configure && make**
to compile the project. When building from a release **tar.xz** tarball, the configure script
is pre-generated (no need to run **autoconf.sh**).
See **./configure --help** and use the **--disable-[feature]** and **--enable-[feature]** options.

To run the test suite that come with the project, type **make check**.
Note that most tests will need root user privileges and will run dangerous storage failure simulations.
Do **not** run tests with root privilege on production systems! Some tests will need the **scsi_debug**
kernel module to be installed.

For more details, please refer to the
[automake](https://www.gnu.org/software/automake/manual/automake.html) and
[autoconf](https://www.gnu.org/savannah-checkouts/gnu/autoconf/manual/autoconf.html) documentation.

Help!
-----
### Documentation
Please read the following before posting questions to the mailing list so that
you can ask better questions and better understand answers.

* [Frequently asked questions (FAQ)](https://gitlab.com/cryptsetup/cryptsetup/wikis/FrequentlyAskedQuestions),
* [LUKS Specifications](#specification-and-documentation), and
* manuals (aka man page, man pages, man-page) 

The FAQ is available online and in the source code for the project. The specifications are
referenced above in this document. The man pages live within the source tree and should be
available after installation using standard man commands, e.g. **man cryptsetup**.

### Mailing List
For cryptsetup and LUKS related questions, please use the cryptsetup mailing list
[cryptsetup@lists.linux.dev](mailto:cryptsetup@lists.linux.dev),
hosted at [kernel.org subspace](https://subspace.kernel.org/lists.linux.dev.html).
To subscribe send an empty email message to
[cryptsetup+subscribe@lists.linux.dev](mailto:cryptsetup+subscribe@lists.linux.dev).

You can also browse and/or search the mailing [list archive](https://lore.kernel.org/cryptsetup/).
USEnet News (NNTP), Atom feed and git access to the public inbox is available through
[lore.kernel.org](https://lore.kernel.org) service.

The former **dm-crypt** [list archive](https://lore.kernel.org/dm-crypt/) is also available.
