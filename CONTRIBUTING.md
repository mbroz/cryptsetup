Contributing to cryptsetup
==========================
For basic information about the cryptsetup project, please read [README](README.md).

The Cryptsetup project uses free, open-source licenses; details are described in [licensing](README.licensing).

For contribution code or documentation to the cryptsetup project, you must have the necessary rights to the content, and your contribution must be provided under the required license.

We welcome contributions from everyone.

Cryptsetup is an independent project with much volunteer effort, and our resources are limited.
Following the guidelines specified in this file makes it easier for us to process your issue.

Project maintainers can remove or reject abusive or otherwise unacceptable comments or code.

Git repository
--------------
The primary repository is located at [gitlab.com/cryptsetup/cryptsetup](https://gitlab.com/cryptsetup/cryptsetup).
The development branch is ``main``; minor stable releases can use their branches with cherry-picked or backported patches.

There are backup mirrors located at [github.com/mbroz/cryptsetup](https://github.com/mbroz/cryptsetup) and [git.kernel.org/pub/scm/utils/cryptsetup/cryptsetup.git](https://git.kernel.org/pub/scm/utils/cryptsetup/cryptsetup.git).

How to make a bug report
------------------------
To report an issue or feature request, please use GitLab [cryptsetup issue tracker](https://gitlab.com/cryptsetup/cryptsetup/-/issues).

Before reporting an issue, please try to search documentation and existing issues. Always try to reproduce the problem on the latest supported release.
Please *always* collect and attach ``--debug`` log and other information as instructed in the issue template.
Even if you think the problem is obvious, we need logged information about the environment (like versions of kernel modules, etc.).

Please do not report distribution-specific issues if they are not present in the latest upstream release.
For such reports, please use downstream distribution-specific trackers.
If the issue is related to upstream, downstream maintainers will redirect you here, or upstream maintainers will join the discussion.

If you think that you found some security bug, please follow the instructions in the [SECURITY](SECURITY.md) file.

How to contribute changes to cryptsetup
---------------------------------------
The following notes are a very short introduction to cryptsetup internal processes and an overview of generic rules that should be followed for all changes.

Changes from developers and external contributors should go through the GitLab repository [merge reguests](https://gitlab.com/cryptsetup/cryptsetup/-/merge_requests).
Alternatively (for trivial changes), you can send a patch to [cryptsetup mailing list](mailto:cryptsetup@lists.linux.dev).

Please do not write personal emails with questions or patches to maintainers and developers.

### Project structure
Cryptsetup projects include a libcryptsetup library, tools, token plugins, documentation, and a test suite.

Cryptsetup library (libcryptsetup) exports [versioned symbols](lib/libcryptsetup.sym).
Tools (cryptsetup, veritysetup, integritysetup) use libcryptsetup shared library.
Some isolated parts in the lib directory can be reused for tools (the source is recompiled).

The basic directory structure in the repository is
```
├── docs - Documentation and release notes.
├── lib  - libcryptsetup implementation
│   ├── bitlk           - Bitlocker format
│   ├── crypto_backend  - Cryptography backend
│   ├── fvault2         - FileVault2 format
│   ├── integrity       - Linux dm-integrity interface
│   ├── loopaes         - Linux LoopAES format
│   ├── luks1           - LUKS1 format
│   ├── luks2           - LUKS2 format including OPAL2 SED
│   ├── tcrypt          - TrueCrypt / VeraCrypt format
│   └── verity          - Linux dm-verity interface
├── man - Manual pages (in AsciiDoc format)
├── misc - Miscellaneous additions
├── po - Translation files
├── scripts - Scripts for system configuration
├── src - Tools implementation
├── tests - Testsuite (test units, regression tests, fuzzing)
└── tokens - Token plugins
```
### Coordination with other projects
The cryptsetup tools and library use low-level functions that depend on many other subsystems.
Currently, the project is supported only for Linux (it will not work on Android or other systems).

Cryptsetup project requires some parts of the Linux kernel, notably the *Device Mapper* (dm-crypt, dm-integrity, dm-verity, dm-zero modules) and kernel *userspace cryptographic interface*.
Missing kernel interface can significantly limit (or even disallow) cryptsetup functionality.

Integration in operating systems also depends on several other projects, most notably *systemd* (that implements its own tooling using libcryptsetup) and *util-Linux* (*blkid* parsing of supported format metadata). Some changes must be synchronized in all needed places (kernel, blkid, libcryptsetup).

Several other projects implement their own token metadata (either through binary token plugins or through generic libcryptsetup JSON token access functions).

### Used cryptography algorithms
Cryptsetup avoids implementing cryptographic primitives but uses cryptographic libraries.
Exceptions were PBKDF internal implementations - PBKDF2 and Argon2 until these were integrated into major cryptographic libraries.

Cryptsetup can be compiled with several cryptographic libraries backend (OpenSSL, libgcrypt, Nettle, NSS, and Linux kernel userspace API).
OpenSSL is the default and strongly recommended configuration.

If the cryptographic library does not implement some cryptographic primitive (for example, if running in a FIPS-140 environment or just
because it does not include it at all), functionality could be limited.

### Configuration and versioning
Cryptsetup can be configured using *Autoconf* or *Meson*. Autoconf support is being deprecated in the long term.
Currently, all new configuration options must be implemented in both systems.

Cryptsetup intentionally does not use a system configuration file (located in /etc).
All functionality must be determined dynamically.

All related /etc configuration files (crypttab, fstab and others) are maintained by systemd (in some legacy distributions by cryptsetup downstream).

Cryptsetup uses [semantic versioning](https://semver.org/).
Major and minor releases are always based on the main git branch; the minor stable (patch) versions can have some specific branch with backported or cherry-picked patches (from the main branch).
Usually, minor releases happen twice per year and stable patch updates according to reported bugs (in 1-3 month intervals).

### Compilation and debugging
The library and tools are written in C language; we require C99 and support gcc and Clang compilers.
Manual pages are generated from AsciiDoc sources and libcryptsetup API documentation by Doxygen (from libcryptsetup.h comments).
Testsuite is a combination of local C utilities, fuzzing implementation in C++, bash scripts, and uses many other system utilities.

All tools contain compiled-in debug messages that are available through --debug options.

With Autoconf and libtool, you can run the cryptsetup tool in the debugger without installation using this one-line script:
```
libtool --mode=execute gdb --args ./cryptsetup --debug $@
```
This will ensure that a properly compiled libcryptsetup file is used.

### Coding style
Cryptsetup uses [Linux kernel coding style](https://cdn.kernel.org/doc/html/latest/process/coding-style.html) for libcryptsetup and tools (where applicable) with some additional notes:
- Use tabulators for indentation; the line should not exceed 100 characters with an 8-character tabulator. Otherwise, use a tab of any length. :-).
- The minimal C standard required is C99.
- The ``goto`` use is allowed only for error path (``goto out`` for common code path, ``goto err`` for specific error code path).
- Split patches per change; do not submit huge patches combining several changes.
- Use an elaborative description in the patch header.
- No need to use sign-off-by lines.
- Use name prefixes (``crypt_``, ``LUKS2_`` and similar).
- Avoid extensive preprocessor use (specifically conditional ``#if`` or ``#ifdef`` sections).
- To check detected configuration options stored in config.h, always use ``#if SOMETHING`` (do NOT use ``#ifdef``).
- Use output only through ``log_err, log_std, log_verbose, log_dbg`` macros.
  The ``log_dbg`` is always in English; the others should be wrapped in the ``_()`` macro for translation.
- Use ``assert()`` but only for simple invariants and variables (avoid calling functions).
  Do not use assert for user-defined input (this should be a normal error path).
- The code style is quite relaxed in testing scripts (code there is not intended for production use).

### General rules and testing
- Cryptsetup should work on all architectures supported by the Linux kernel.
Only very few functionalities require specific hardware (notably Opal SED support).
If you want to introduce some specific hardware support, please discuss it with the maintainers first.

- All code changes should go through merge requests and reviews.
Code can be merged after review approval (done by someone with the commit right to the development repository), but reviews from external people are very welcome, too.

- All new functionality must come with at least rudimentary coverage in the test suite.
Always run the test suite before opening the merge request (``make check`` with root privilege).

- We have continuous integration (CI) that runs many tests automatically, but the output is not directly visible for external merge request authors (for security reasons).
All CI scripts are available in .gitlab and .github folders in the project repository.

  Maintainers will provide you log files if anything fails. Your code must produce no warnings before it is merged.

- We run compilation with many extended [gcc](.gitlab/ci/gcc-Wall) and [Clang](.gitlab/ci/clang-Wall) warnings and include some analyzers, notably
  - [Coverity](https://scan.coverity.com), GitHub CodeQL, Clang scan-build, and gcc static analyzer, and
  - fuzzing integrated in [OSS-fuzz project](https://github.com/google/oss-fuzz/tree/master/projects/cryptsetup).

- Testsuite can also partially run under Valgrind dynamic analyzer with ``make valgrind-check``.
