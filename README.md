![LUKS logo](https://gitlab.com/cryptsetup/cryptsetup/wikis/luks-logo.png)

What the ...?
=============
**Cryptsetup** is a utility used to conveniently set up disk encryption based
on the [DMCrypt](https://gitlab.com/cryptsetup/cryptsetup/wikis/DMCrypt) kernel module.

These include **plain** **dm-crypt** volumes, **LUKS** volumes, **loop-AES**,
**TrueCrypt** (including **VeraCrypt** extension) and **BitLocker** formats.

The project also includes a **veritysetup** utility used to conveniently setup
[DMVerity](https://gitlab.com/cryptsetup/cryptsetup/wikis/DMVerity) block integrity checking kernel module
and, since version 2.0,  **integritysetup** to setup
[DMIntegrity](https://gitlab.com/cryptsetup/cryptsetup/wikis/DMIntegrity) block integrity kernel module.


LUKS Design
-----------
**LUKS** is the standard for Linux hard disk encryption. By providing a standard on-disk-format, it does not  
only facilitate compatibility among distributions, but also provides secure management of multiple user passwords.  
LUKS stores all necessary setup information in the partition header, enabling to transport or migrate data seamlessly.

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

**The latest stable cryptsetup version is 2.3.2**
  * [cryptsetup-2.3.2.tar.xz](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.3/cryptsetup-2.3.2.tar.xz)
  * Signature [cryptsetup-2.3.2.tar.sign](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.3/cryptsetup-2.3.2.tar.sign)
    _(You need to decompress file first to check signature.)_
  * [Cryptsetup 2.3.2 Release Notes](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.3/v2.3.2-ReleaseNotes).

Previous versions
 * [Version 2.3.1](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.3/cryptsetup-2.3.1.tar.xz) -
   [Signature](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.3/cryptsetup-2.3.1.tar.sign) -
   [Release Notes](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.3/v2.3.1-ReleaseNotes).
 * [Version 2.2.2](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.2/cryptsetup-2.2.2.tar.xz) -
   [Signature](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.2/cryptsetup-2.2.2.tar.sign) -
   [Release Notes](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.2/v2.2.2-ReleaseNotes).
 * [Version 2.0.6](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.0/cryptsetup-2.0.6.tar.xz) -
   [Signature](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.0/cryptsetup-2.0.6.tar.sign) -
   [Release Notes](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.0/v2.0.6-ReleaseNotes).
 * [Version 1.7.5](https://www.kernel.org/pub/linux/utils/cryptsetup/v1.7/cryptsetup-1.7.5.tar.xz) -
   [Signature](https://www.kernel.org/pub/linux/utils/cryptsetup/v1.7/cryptsetup-1.7.5.tar.sign) -
   [Release Notes](https://www.kernel.org/pub/linux/utils/cryptsetup/v1.7/v1.7.5-ReleaseNotes).

Source and API docs
-------------------
For development version code, please refer to [source](https://gitlab.com/cryptsetup/cryptsetup/tree/master) page,
mirror on [kernel.org](https://git.kernel.org/cgit/utils/cryptsetup/cryptsetup.git/) or [GitHub](https://github.com/mbroz/cryptsetup).

For libcryptsetup documentation see [libcryptsetup API](https://mbroz.fedorapeople.org/libcryptsetup_API/) page.

The libcryptsetup API/ABI changes are tracked in [compatibility report](https://abi-laboratory.pro/tracker/timeline/cryptsetup/).

NLS PO files are maintained by [TranslationProject](http://translationproject.org/domain/cryptsetup.html).

Help!
-----
Please always read [FAQ](https://gitlab.com/cryptsetup/cryptsetup/wikis/FrequentlyAskedQuestions) first.
For cryptsetup and LUKS related questions, please use the dm-crypt mailing list, [dm-crypt@saout.de](mailto:dm-crypt@saout.de).

If you want to subscribe just send an empty mail to [dm-crypt-subscribe@saout.de](mailto:dm-crypt-subscribe@saout.de).

You can also browse [list archive](http://www.saout.de/pipermail/dm-crypt/) or read it through
[web interface](https://marc.info/?l=dm-crypt).
