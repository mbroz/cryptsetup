![LUKS logo](https://gitlab.com/cryptsetup/cryptsetup/wikis/luks-logo.png)

What the ...?
=============
**Cryptsetup** is a utility used to conveniently set up disk encryption based
on the [DMCrypt](https://gitlab.com/cryptsetup/cryptsetup/wikis/DMCrypt) kernel module.

These include **plain** **dm-crypt** volumes, **LUKS** volumes, **loop-AES**,
**TrueCrypt** (including **VeraCrypt** extension), **BitLocker** and **FileVault2** formats.

The project also includes a **veritysetup** utility used to conveniently setup
[DMVerity](https://gitlab.com/cryptsetup/cryptsetup/wikis/DMVerity) block integrity checking kernel module
and **integritysetup** to setup
[DMIntegrity](https://gitlab.com/cryptsetup/cryptsetup/wikis/DMIntegrity) block integrity kernel module.

LUKS Design
-----------
**LUKS** is the standard for Linux hard disk encryption. By providing a standard on-disk-format, it does not  
only facilitate compatibility among distributions, but also provides secure management of multiple user passwords.  
LUKS stores all necessary setup information in the partition header, enabling to transport or migrate data seamlessly.

### Specifications

Last version of the LUKS2 format specification is
[available here](https://gitlab.com/cryptsetup/LUKS2-docs).

Last version of the LUKS1 format specification is
[available here](https://www.kernel.org/pub/linux/utils/cryptsetup/LUKS_docs/on-disk-format.pdf).

Why LUKS?
---------
 * compatibility via standardization,
 * secure against low entropy attacks,
 * support for multiple keys,
 * effective passphrase revocation,
 * free.

[Project home page](https://gitlab.com/cryptsetup/cryptsetup/).
-----------------

[Frequently asked questions (FAQ)](https://gitlab.com/cryptsetup/cryptsetup/wikis/FrequentlyAskedQuestions)
--------------------------------

Download
--------
All release tarballs and release notes are hosted on [kernel.org](https://www.kernel.org/pub/linux/utils/cryptsetup/).

**The latest stable cryptsetup release candidate version is 2.6.0-rc0**
  * [cryptsetup-2.6.0-rc0.tar.xz](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.6/cryptsetup-2.6.0-rc0.tar.xz)
  * Signature [cryptsetup-2.6.0-rc0.tar.sign](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.6/cryptsetup-2.6.0-rc0.tar.sign)
    _(You need to decompress file first to check signature.)_
  * [Cryptsetup 2.6.0-rc0 Release Notes](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.6/v2.6.0-rc0-ReleaseNotes).

**The latest stable cryptsetup version is 2.5.0**
  * [cryptsetup-2.5.0.tar.xz](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.5/cryptsetup-2.5.0.tar.xz)
  * Signature [cryptsetup-2.5.0.tar.sign](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.5/cryptsetup-2.5.0.tar.sign)
    _(You need to decompress file first to check signature.)_
  * [Cryptsetup 2.5.0 Release Notes](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.5/v2.5.0-ReleaseNotes).

Previous versions
 * [Version 2.4.3](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.4/cryptsetup-2.4.3.tar.xz) -
   [Signature](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.4/cryptsetup-2.4.3.tar.sign) -
   [Release Notes](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.4/v2.4.3-ReleaseNotes).
 * [Version 1.7.5](https://www.kernel.org/pub/linux/utils/cryptsetup/v1.7/cryptsetup-1.7.5.tar.xz) -
   [Signature](https://www.kernel.org/pub/linux/utils/cryptsetup/v1.7/cryptsetup-1.7.5.tar.sign) -
   [Release Notes](https://www.kernel.org/pub/linux/utils/cryptsetup/v1.7/v1.7.5-ReleaseNotes).

Source and API docs
-------------------
For development version code, please refer to [source](https://gitlab.com/cryptsetup/cryptsetup/tree/master) page,
mirror on [kernel.org](https://git.kernel.org/cgit/utils/cryptsetup/cryptsetup.git/) or [GitHub](https://github.com/mbroz/cryptsetup).

For libcryptsetup documentation see [libcryptsetup API](https://mbroz.fedorapeople.org/libcryptsetup_API/) page.

The libcryptsetup API/ABI changes are tracked in [compatibility report](https://abi-laboratory.pro/tracker/timeline/cryptsetup/).

NLS PO files are maintained by [TranslationProject](https://translationproject.org/domain/cryptsetup.html).

Required packages
-----------------
All distributions provide cryptsetup as distro package. If you need to compile cryptsetup yourself, some packages are required for compilation. Please always prefer distro specific build tools to manually configuring cryptsetup.

Here is the list of packages needed for the compilation of project for particular distributions:
 * For Fedora: `git gcc make autoconf automake gettext-devel pkgconfig openssl-devel popt-devel device-mapper-devel libuuid-devel json-c-devel libblkid-devel findutils libtool libssh-devel tar`. Optionally `libargon2-devel libpwquality-devel`. To run the internal testsuite you also need to install `sharutils device-mapper jq vim-common expect keyutils netcat shadow-utils openssh-clients openssh sshpass`.

 * For Debian and Ubuntu: `git gcc make autoconf automake autopoint pkg-config libtool gettext libssl-dev libdevmapper-dev libpopt-dev uuid-dev libsepol1-dev libjson-c-dev libssh-dev libblkid-dev tar`. Optionally `libargon2-0-dev libpwquality-dev`. To run the internal testsuite you also need to install `sharutils dmsetup jq xxd expect keyutils netcat passwd openssh-client sshpass`

Note that the list could change as the distributions evolve.

Compilation
-----------
The cryptsetup project uses **automake** and **autoconf** system to generate all needed files for compilation. If you check it from the git snapshot, use ``./autogen.sh && ./configure && make`` to compile the project. If you use downloaded released ``*.tar.xz`` archive, the configure script is already pre-generated (no need to run ``autoconf.sh``).
See ``./configure --help`` and use ``--disable-*`` and ``--enable-*`` options.

For running the test suite that come with the project, type ``make check``.
Note that most tests will need root user privileges and run many dangerous storage fail simulations.
Do **not** run tests with root privilege on production systems! Some tests will need scsi_debug kernel module to be available.

For more details, please refer to [automake](https://www.gnu.org/software/automake/manual/automake.html) and [autoconf](https://www.gnu.org/savannah-checkouts/gnu/autoconf/manual/autoconf.html) manuals.

Help!
-----

### Documentation

Please read the following documentation before posting questions in the mailing list.   You will be able to ask better questions and better understand the answers.  

* [FAQ](https://gitlab.com/cryptsetup/cryptsetup/wikis/FrequentlyAskedQuestions) 
* LUKS Specifications
* manuals (aka man page, man pages, man-page) 

The FAQ is online and in the source code for the project.  The Specifications are referenced above in this document.  The man pages are in source and should be available after installation using standard man commands.  e.g.  man cryptsetup

### Mailing List

For cryptsetup and LUKS related questions, please use the cryptsetup mailing list [cryptsetup@lists.linux.dev](mailto:cryptsetup@lists.linux.dev), hosted at [kernel.org subspace](https://subspace.kernel.org/lists.linux.dev.html).
To subscribe send an empty mail to [cryptsetup+subscribe@lists.linux.dev](mailto:cryptsetup+subscribe@lists.linux.dev).

You can also browse and/or search the mailing [list archive](https://lore.kernel.org/cryptsetup/).
News (NNTP), Atom feed and git access to public inbox is available through [lore.kernel.org](https://lore.kernel.org) service.

The former dm-crypt [list archive](https://lore.kernel.org/dm-crypt/) is also available.
