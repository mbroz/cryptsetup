![LUKS logo](https://gitlab.com/cryptsetup/cryptsetup/wikis/luks-logo.png)

What the ...?
=============
**Cryptsetup** is a utility used to conveniently set up disk encryption based
on the [DMCrypt](https://gitlab.com/cryptsetup/cryptsetup/wikis/DMCrypt) kernel module.

These include **plain** **dm-crypt** volumes, **LUKS** volumes, **loop-AES**,
**TrueCrypt** (including **VeraCrypt** extension) and **BitLocker** formats.

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

**The latest stable cryptsetup version is 2.4.3**
  * [cryptsetup-2.4.3.tar.xz](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.4/cryptsetup-2.4.3.tar.xz)
  * Signature [cryptsetup-2.4.3.tar.sign](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.4/cryptsetup-2.4.3.tar.sign)
    _(You need to decompress file first to check signature.)_
  * [Cryptsetup 2.4.3 Release Notes](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.4/v2.4.3-ReleaseNotes).

Previous versions
 * [Version 2.3.7](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.3/cryptsetup-2.3.7.tar.xz) -
   [Signature](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.3/cryptsetup-2.3.7.tar.sign) -
   [Release Notes](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.3/v2.3.7-ReleaseNotes).
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
For available compile options, check ``configure --help`` for more info. If you are using a git snapshot, you need to generate a configure script with ``autogen.sh`` script.

Here is the list of packages needed for the compilation of project for particular distributions:
 * For Fedora: `git gcc make autoconf automake gettext-devel pkgconfig openssl-devel popt-devel device-mapper-devel libuuid-devel json-c-devel libblkid-devel findutils libtool libssh-devel tar`. Optionally `libargon2-devel libpwquality-devel`. To run the internal testsuite you also need to install `sharutils device-mapper jq vim-common expect keyutils netcat shadow-utils openssh-clients openssh sshpass`.

 * For Debian and Ubuntu: `git gcc make autoconf automake autopoint pkg-config libtool gettext libssl-dev libdevmapper-dev libpopt-dev uuid-dev libsepol1-dev libjson-c-dev libssh-dev libblkid-dev tar`. Optionally `libargon2-0-dev libpwquality-dev`. To run the internal testsuite you also need to install `sharutils dmsetup jq xxd expect keyutils netcat passwd openssh-client sshpass`

Note that the list could change as the distributions evolve.

Help!
-----

### Documentation

Please read the following documentation before posting questions in the mailing list.   You will be able to ask better questions and better understand the answers.  

* [FAQ](https://gitlab.com/cryptsetup/cryptsetup/wikis/FrequentlyAskedQuestions) 
* LUKS Specifications
* manuals (aka man page, man pages, man-page) 

The FAQ is online and in the source code for the project.  The Specifications are referenced above in this document.  The man pages are in source and should be available after installation using standard man commands.  e.g.  man cryptsetup

### Mailing List

For cryptsetup and LUKS related questions, please use the dm-crypt mailing list, [dm-crypt@saout.de](mailto:dm-crypt@saout.de).  To subscribe send an empty mail to [dm-crypt-subscribe@saout.de](mailto:dm-crypt-subscribe@saout.de).

You can also browse and/or search the mailing list archives using the following resources:

* [list archive](https://www.saout.de/pipermail/dm-crypt/) 
* [web interface on lore.kernel.org](https://lore.kernel.org/dm-crypt/) 
* [marc.info](https://marc.info/?l=dm-crypt).
