# Frequently Asked Questions Cryptsetup/LUKS

# Sections
[1. General Questions](#1-general-questions)  
[2. Setup](#2-setup)  
[3. Common Problems](#3-common-problems)  
[4. Troubleshooting](#4-troubleshooting)  
[5. Security Aspects](#5-security-aspects)  
[6. Backup and Data Recovery](#6-backup-and-data-recovery)  
[7. Interoperability with other Disk Encryption Tools](#7-interoperability-with-other-disk-encryption-tools)  
[8. Issues with Specific Versions of cryptsetup](#8-issues-with-specific-versions-of-cryptsetup)  
[9. The Initrd question](#9-the-initrd-question)  
[10. LUKS2 Questions](#10-luks2-questions)  
[11. References and Further Reading](#11-references-and-further-reading)  
[A. Contributors](#a-contributors)  

# 1. General Questions


  * **1.1 What is this?**

  This is the FAQ (Frequently Asked Questions) for cryptsetup.  It covers
  Linux disk encryption with plain dm-crypt (one passphrase, no
  management, no metadata on disk) and LUKS (multiple user keys with one
  volume key, anti-forensic features, metadata block at start of device,
  ...).  The latest version of this FAQ should usually be available at
  https://gitlab.com/cryptsetup/cryptsetup/wikis/FrequentlyAskedQuestions


  * **1.2 WARNINGS**

  LUKS2 COMPATIBILITY: This FAQ was originally written for LUKS1, not
  LUKS2.  Hence regarding LUKS2, some of the answers found here may not
  apply.  Updates for LUKS2 have been done and anything not applying to
  LUKS2 should clearly say LUKS1.  However, this is a Frequently Asked
  Questions, and questions for LUKS2 are limited at this time or at least
  those that have reached me are.  In the following, "LUKS" refers to both
  LUKS1 and LUKS2.
 
  The LUKS1 on-disk format specification is at  
  https://cdn.kernel.org/pub/linux/utils/cryptsetup/LUKS_docs/on-disk-format.pdf  
  The LUKS2 on-disk format specification is at  
  https://gitlab.com/cryptsetup/LUKS2-docs

  ATTENTION: If you are going to read just one thing, make it the section
  on Backup and Data Recovery.  By far the most questions on the
  cryptsetup mailing list are from people that managed to damage the start
  of their LUKS partitions, i.e.  the LUKS header.  In most cases, there
  is nothing that can be done to help these poor souls recover their data. 
  Make sure you understand the problem and limitations imposed by the LUKS
  security model BEFORE you face such a disaster!  In particular, make
  sure you have a current header backup before doing any potentially
  dangerous operations.  The LUKS2 header should be a bit more resilient
  as critical data starts later and is stored twice, but you can decidedly
  still destroy it or a keyslot permanently by accident.

  DEBUG COMMANDS: While the --debug and --debug-json options should not
  leak secret data, "strace" and the like can leak your full passphrase. 
  Do not post an strace output with the correct passphrase to a
  mailing-list or online!  See Item 4.5 for more explanation.

  SSDs/FLASH DRIVES: SSDs and Flash are different.  Currently it is
  unclear how to get LUKS or plain dm-crypt to run on them with the full
  set of security assurances intact.  This may or may not be a problem,
  depending on the attacker model.  See Section 5.19.

  BACKUP: Yes, encrypted disks die, just as normal ones do.  A full backup
  is mandatory, see Section "6.  Backup and Data Recovery" on options for
  doing encrypted backup.

  CLONING/IMAGING: If you clone or image a LUKS container, you make a copy
  of the LUKS header and the volume key will stay the same!  That means
  that if you distribute an image to several machines, the same volume key
  will be used on all of them, regardless of whether you change the
  passphrases.  Do NOT do this!  If you do, a root-user on any of the
  machines with a mapped (decrypted) container or a passphrase on that
  machine can decrypt all other copies, breaking security.  See also Item
  6.15.

  DISTRIBUTION INSTALLERS: Some distribution installers offer to create
  LUKS containers in a way that can be mistaken as activation of an
  existing container.  Creating a new LUKS container on top of an existing
  one leads to permanent, complete and irreversible data loss.  It is
  strongly recommended to only use distribution installers after a
  complete backup of all LUKS containers has been made.

  UBUNTU INSTALLER: In particular the Ubuntu installer seems to be quite
  willing to kill LUKS containers in several different ways.  Those
  responsible at Ubuntu seem not to care very much (it is very easy to
  recognize a LUKS container), so treat the process of installing Ubuntu
  as a severe hazard to any LUKS container you may have.

  NO WARNING ON NON-INTERACTIVE FORMAT: If you feed cryptsetup from STDIN
  (e.g.  via GnuPG) on LUKS format, it does not give you the warning that
  you are about to format (and e.g.  will lose any pre-existing LUKS
  container on the target), as it assumes it is used from a script.  In
  this scenario, the responsibility for warning the user and possibly
  checking for an existing LUKS header is shifted to the script.  This is
  a more general form of the previous item.

  LUKS PASSPHRASE IS NOT THE VOLUME KEY: The LUKS passphrase is not used
  in deriving the volume key.  It is used in decrypting a volume key that
  is randomly selected on header creation.  This means that if you create
  a new LUKS header on top of an old one with exactly the same parameters
  and exactly the same passphrase as the old one, it will still have a
  different volume key and your data will be permanently lost.

  PASSPHRASE CHARACTER SET: Some people have had difficulties with this
  when upgrading distributions.  It is highly advisable to only use the 95
  printable characters from the first 128 characters of the ASCII table,
  as they will always have the same binary representation.  Other
  characters may have different encoding depending on system configuration
  and your passphrase will not work with a different encoding.  A table of
  the standardized first 128 ASCII characters can, e.g.  be found on
  https://en.wikipedia.org/wiki/ASCII

  KEYBOARD NUM-PAD: Apparently some pre-boot authentication environments
  (these are done by the distro, not by cryptsetup, so complain there)
  treat digits entered on the num-pad and ones entered regularly
  different.  This may be because the BIOS USB keyboard driver is used and
  that one may have bugs on some computers.  If you cannot open your
  device in pre-boot, try entering the digits over the regular digit keys.


  * **1.3 System specific warnings**

  - The Ubuntu Natty uinstaller has a "won't fix" defect that may destroy
  LUKS containers.  This is quite old an not relevant for most people. 
  Reference:
  https://bugs.launchpad.net/ubuntu/+source/partman-crypto/+bug/420080


  * **1.4 My LUKS-device is broken! Help!**

  First: Do not panic! In many cases the data is still recoverable.
  Do not do anything hasty! Steps:

  - Take some deep breaths. Maybe add some relaxing music.  This may
  sound funny, but I am completely serious.  Often, critical damage is
  done only after the initial problem.

  - Do not reboot. The keys may still be in the kernel if the device is
  mapped.

  - Make sure others do not reboot the system.

  - Do not write to your disk without a clear understanding why this will
  not make matters worse.  Do a sector-level backup before any writes. 
  Often you do not need to write at all to get enough access to make a
  backup of the data.

  - Relax some more.

  - Read section 6 of this FAQ.

  - Ask on the mailing-list if you need more help.


  * **1.5 Who wrote this?**

  Current FAQ maintainer is Arno Wagner <arno@wagner.name>.  If you want
  to send me encrypted email, my current PGP key is DSA key CB5D9718,
  fingerprint 12D6 C03B 1B30 33BB 13CF B774 E35C 5FA1 CB5D 9718.

  Other contributors are listed at the end.  If you want to contribute,
  send your article, including a descriptive headline, to the maintainer,
  or the dm-crypt mailing list with something like "FAQ ..." 
  in the subject.  You can also send more raw information and have
  me write the section.  Please note that by contributing to this FAQ,
  you accept the license described below.

  This work is licensed under a Creative Commons CC-BY-SA-4.0
  "Attribution-ShareAlike 4.0 International" license which means
  distribution is unlimited, you may create derived works, but
  attributions to original authors and this license statement must be
  retained and the derived work must be under the same license.
  See https://creativecommons.org/licenses/by-sa/4.0/ for more details.

  * **1.6 Where is the project website?**

  There is the project website at
  https://gitlab.com/cryptsetup/cryptsetup/ Please do not post
  questions there, nobody will read them.  Use the mailing-list
  instead.


  * **1.7 Is there a mailing-list?**

  Instructions on how to subscribe to the mailing-list are on the
  project website.  People are generally helpful and friendly on the
  list.

  The question of how to unsubscribe from the list does crop up sometimes. 
  For this you need your list management URL 
  https://subspace.kernel.org/lists.linux.dev.html. Go to the URL mentioned 
  in the email and select "unsubscribe".

  Alternatively, you can send an empty Email to cryptsetup+help@lists.linux.dev. 
  Make sure to send it from your list address.

  The mailing list archive is here:
  https://lore.kernel.org/cryptsetup/

  The legacy dm-crypt mailing list archive is here:
  https://lore.kernel.org/dm-crypt/


  * **1.8 Unsubscribe from the mailing-list**

  Send mail to cryptsetup+unsubscribe@lists.linux.dev from the subscribed account. 
  You will get an email with instructions.

  Basically, you just have to respond to it unmodified to get
  unsubscribed.  The listserver admin functions are not very fast.  It can
  take 15 minutes or longer for a reply to arrive (I suspect greylisting
  is in use), so be patient.

  Also note that nobody on the list can unsubscribe you, sending demands
  to be unsubscribed to the list just annoys people that are entirely
  blameless for you being subscribed.

  If you are subscribed, a subscription confirmation email was sent to
  your email account and it had to be answered before the subscription
  went active.  The confirmation emails from the listserver have subjects
  like these (with other numbers):
```
    Subject: Confirm subscription to cryptsetup@lists.linux.dev
```
  and are sent from cryptsetup+help@lists.linux.dev.  You should check whether
  you have anything like it in your sent email folder.  If you find
  nothing and are sure you did not confirm, then you should look into a
  possible compromise of your email account.

  * **1.9 What can I do if cryptsetup is running out of memory?**

  Memory issues are generally related to the key derivation function.  You may
  be able to tune usage with the options --pbkdf-memory or --pbkdf pbkdf2.


  * **1.10 Can cryptsetup be run without root access?**

  Elevated privileges are required to use cryptsetup and LUKS.  Some operations
  require root access.  There are a few features which will work without root 
  access with the right switches but there are caveats.


  * **1.11 What are the problems with running as non root?**

  The first issue is one of permissions to devices.  Generally, root or a group
  such as disk has ownership of the storage devices.  The non root user will
  need write access to the block device used for LUKS.

  Next, file locking is managed in /run/cryptsetup.  You may use 
  --disable-locks but cryptsetup will no longer protect you from race 
  conditions and problems with concurrent access to the same devices.

  Also, device mapper requires root access.  cryptsetup uses device mapper to 
  manage the decrypted container.

  * **1.12 How can I report an issue in the cryptsetup project?**

  Before reporting any issue, please be sure you are using the latest
  upstream version and that you read the documentation (and this FAQ).

  If you think you have discovered an issue, please report it through
  the project issue tracker [New issue](https://gitlab.com/cryptsetup/cryptsetup/issues).
  For a possible security issue, please use the confidential checkbox.

  Please fill in all information requested in the report template
  (specifically add debug output with all run environment data).
  Do not trim the output; debug output does not include private data.


# 2. Setup

  * **2.1 LUKS Container Setup mini-HOWTO**

  This item tries to give you a very brief list of all the steps you
  should go through when creating a new LUKS encrypted container, i.e.
  encrypted disk, partition or loop-file.

  01) All data will be lost, if there is data on the target, make a
  backup.

  02) Make very sure you use the right target disk, partition or
  loop-file.

  03) If the target was in use previously, it is a good idea to wipe it
  before creating the LUKS container in order to remove any trace of old
  file systems and data.  For example, some users have managed to run
  e2fsck on a partition containing a LUKS container, possibly because of
  residual ext2 superblocks from an earlier use.  This can do arbitrary
  damage up to complete and permanent loss of all data in the LUKS
  container.

  To just quickly wipe file systems (old data may remain), use
```
    wipefs -a <target device>
```
  To wipe file system and data, use something like
```
    cat /dev/zero > <target device>
```
  This can take a while.  To get a progress indicator, you can use the
  tool dd_rescue (->google) instead or use my stream meter "wcs" (source
  here: https://www.tansi.org/tools/index.html) in the following fashion:
```
    cat /dev/zero | wcs > <target device>
```
  Plain "dd" also gives you the progress on a SIGUSR1, see its man-page.
  The GNU "dd" command supports the "status=progress" operand that gives you
  the progress without having to send it any signal.

  Be very sure you have the right target, all data will be lost!

  Note that automatic wiping is on the TODO list for cryptsetup, so at
  some time in the future this will become unnecessary.

  Alternatively, plain dm-crypt can be used for a very fast wipe with
  crypto-grade randomness, see Item 2.19

  04) Create the LUKS container.  

  LUKS1:
```
    cryptsetup luksFormat --type luks1 <target device>
```   
  LUKS2:
```
    cryptsetup luksFormat --type luks2 <target device>
```

  Just follow the on-screen instructions.

  Note: Passphrase iteration count is based on time and hence security
  level depends on CPU power of the system the LUKS container is created
  on.  For example on a Raspberry Pi and LUKS1, I found some time ago that
  the iteration count is 15 times lower than for a regular PC (well, for
  my old one).  Depending on security requirements, this may need
  adjustment.  For LUKS1, you can just look at the iteration count on
  different systems and select one you like.  You can also change the
  benchmark time with the -i parameter to create a header for a slower
  system.

  For LUKS2, the parameters are more complex.  ARGON2 has iteration,
  parallelism and memory parameter.  cryptsetup actually may adjust the
  memory parameter for time scaling.  Hence to use -i is the easiest way
  to get slower or faster opening (default: 2000 = 2sec).  Just make sure
  to not drop this too low or you may get a memory parameter that is to
  small to be secure.  The luksDump command lists the memory parameter of
  a created LUKS2 keyslot in kB.  That parameter should probably be not
  much lower than 100000, i.e.  100MB, but don't take my word for it.

  05) Map the container. Here it will be mapped to /dev/mapper/c1:
```
    cryptsetup luksOpen <target device> c1
```
  06) (Optionally) wipe the container (make sure you have the right
      target!): 
```
    cat /dev/zero > /dev/mapper/c1
```
  This will take a while.  Note that this creates a small information
  leak, as an attacker can determine whether a 512 byte block is zero if
  the attacker has access to the encrypted container multiple times. 
  Typically a competent attacker that has access multiple times can
  install a passphrase sniffer anyways, so this leakage is not very
  significant.  For getting a progress indicator, see step 03.

  07) Create a file system in the mapped container, for example an
  ext3 file system (any other file system is possible):
```
    mke2fs -j /dev/mapper/c1
```
  08) Mount your encrypted file system, here on /mnt:
```
    mount /dev/mapper/c1 /mnt
```
  09) Make a LUKS header backup and plan for a container backup.
      See Section 6 for details.

  Done.  You can now use the encrypted file system to store data.  Be sure
  to read through the rest of the FAQ, these are just the very basics.  In
  particular, there are a number of mistakes that are easy to make, but
  will compromise your security.


  * **2.2 LUKS on partitions or raw disks? What about RAID?**

  Also see Item 2.8.  
  This is a complicated question, and made more so by the availability of
  RAID and LVM.  I will try to give some scenarios and discuss advantages
  and disadvantages.  Note that I say LUKS for simplicity, but you can do
  all the things described with plain dm-crypt as well.  Also note that
  your specific scenario may be so special that most or even all things I
  say below do not apply.

  Be aware that if you add LVM into the mix, things can get very
  complicated.  Same with RAID but less so.  In particular, data recovery
  can get exceedingly difficult.  Only add LVM if you have a really good
  reason and always remember KISS is what separates an engineer from an
  amateur.  Of course, if you really need the added complexity, KISS is
  satisfied.  But be very sure as there is a price to pay for it.  In
  engineering, complexity is always the enemy and needs to be fought
  without mercy when encountered.

  Also consider using RAID instead of LVM, as at least with the old
  superblock format 0.90, the RAID superblock is in the place (end of
  disk) where the risk of it damaging the LUKS header is smallest and you
  can have your array assembled by the RAID controller (i.e.  the kernel),
  as it should be.  Use partition type 0xfd for that.  I recommend staying
  away from superblock formats 1.0, 1.1 and 1.2 unless you really need
  them.

  Scenarios:

  (1) Encrypted partition: Just make a partition to your liking, and put
  LUKS on top of it and a filesystem into the LUKS container.  This gives
  you isolation of differently-tasked data areas, just as ordinary
  partitioning does.  You can have confidential data, non-confidential
  data, data for some specific applications, user-homes, root, etc. 
  Advantages are simplicity as there is a 1:1 mapping between partitions
  and filesystems, clear security functionality and the ability to
  separate data into different, independent (!) containers.

  Note that you cannot do this for encrypted root, that requires an
  initrd.  On the other hand, an initrd is about as vulnerable to a
  competent attacker as a non-encrypted root, so there really is no
  security advantage to doing it that way.  An attacker that wants to
  compromise your system will just compromise the initrd or the kernel
  itself.  The better way to deal with this is to make sure the root
  partition does not store any critical data and to move that to
  additional encrypted partitions.  If you really are concerned your root
  partition may be sabotaged by somebody with physical access (who would
  however strangely not, say, sabotage your BIOS, keyboard, etc.), protect
  it in some other way.  The PC is just not set-up for a really secure
  boot-chain (whatever some people may claim).

  That said, if you want an encrypted root partition, you have to store 
  an initrd with cryptsetup somewhere else. The traditional approach is
  to have a separate partition under /boot for that. You can also put that 
  initrd on a bootable memory stick, bootable CD or bootable external
  drive as well. The kernel and Grub typically go to the same location 
  as that initrd. A minimal example what such an initrd can look like is 
  given in Section 9.
  
  (2) Fully encrypted raw block device: For this, put LUKS on the raw
  device (e.g.  /dev/sdb) and put a filesystem into the LUKS container, no
  partitioning whatsoever involved.  This is very suitable for things like
  external USB disks used for backups or offline data-storage.

  (3) Encrypted RAID: Create your RAID from partitions and/or full
  devices.  Put LUKS on top of the RAID device, just if it were an
  ordinary block device.  Applications are just the same as above, but you
  get redundancy.  (Side note as many people seem to be unaware of it: You
  can do RAID1 with an arbitrary number of components in Linux.) See also
  Item 2.8.

  (4) Now, some people advocate doing the encryption below the RAID layer. 
  That has several serious problems.  One is that suddenly debugging RAID
  issues becomes much harder.  You cannot do automatic RAID assembly
  anymore.  You need to keep the encryption keys for the different RAID
  components in sync or manage them somehow.  The only possible advantage
  is that things may run a little faster as more CPUs do the encryption,
  but if speed is a priority over security and simplicity, you are doing
  this wrong anyways.  A good way to mitigate a speed issue is to get a
  CPU that does hardware AES as most do today.


  * **2.3 How do I set up encrypted swap?**

  As things that are confidential can end up in swap (keys, passphrases,
  etc.  are usually protected against being swapped to disk, but other
  things may not be), it may be advisable to do something about the issue. 
  One option is to run without swap, which generally works well in a
  desktop-context.  It may cause problems in a server-setting or under
  special circumstances.  The solution to that is to encrypt swap with a
  random key at boot-time.

  NOTE: This is for Debian, and should work for Debian-derived
  distributions.  For others you may have to write your own startup script
  or use other mechanisms.

  01) Add the swap partition to /etc/crypttab. A line like the
  following should do it:
```
    swap  /dev/<partition>  /dev/urandom   swap,noearly
```
  Warning: While Debian refuses to overwrite partitions with a filesystem
  or RAID signature on it, as your disk IDs may change (adding or removing
  disks, failure of disk during boot, etc.), you may want to take
  additional precautions.  Yes, this means that your kernel device names
  like sda, sdb, ...  can change between reboots!  This is not a concern
  if you have only one disk.  One possibility is to make sure the
  partition number is not present on additional disks or also swap there. 
  Another is to encapsulate the swap partition (by making it a 1-partition
  RAID1 or by using LVM), as that gets a persistent identifier. 
  Specifying it directly by UUID does not work, unfortunately, as the UUID
  is part of the swap signature and that is not visible from the outside
  due to the encryption and in addition changes on each reboot with this
  setup.

  Note: Use /dev/random if you are paranoid or in a potential low-entropy
  situation (embedded system, etc.).  This may cause the operation to take
  a long time during boot however.  If you are in a "no entropy"
  situation, you cannot encrypt swap securely.  In this situation you
  should find some entropy, also because nothing else using crypto will be
  secure, like ssh, ssl or GnuPG.

  Note: The "noearly" option makes sure things like LVM, RAID, etc.  are
  running.  As swap is non-critical for boot, it is fine to start it late.

  02) Add the swap partition to /etc/fstab. A line like the following
  should do it:
```
    /dev/mapper/swap none swap sw 0 0
```
  That is it. Reboot or start it manually to activate encrypted swap. 
  Manual start would look like this:
```
    /etc/init.d/cryptdisks start
    swapon /dev/mapper/swap
```

  * **2.4 What is the difference between "plain" and LUKS format?**

  First, unless you happen to understand the cryptographic background
  well, you should use LUKS.  It does protect the user from a lot of
  common mistakes.  Plain dm-crypt is for experts.

  Plain format is just that: It has no metadata on disk, reads all
  parameters from the commandline (or the defaults), derives a volume-key
  from the passphrase and then uses that to de-/encrypt the sectors of the
  device, with a direct 1:1 mapping between encrypted and decrypted
  sectors.

  Primary advantage is high resilience to damage, as one damaged encrypted
  sector results in exactly one damaged decrypted sector.  Also, it is not
  readily apparent that there even is encrypted data on the device, as an
  overwrite with crypto-grade randomness (e.g.  from
  /dev/urandom) looks exactly the same on disk.

  Side-note: That has limited value against the authorities.  In civilized
  countries, they cannot force you to give up a crypto-key anyways.  In
  quite a few countries around the world, they can force you to give up
  the keys (using imprisonment or worse to pressure you, sometimes without
  due process), and in the worst case, they only need a nebulous
  "suspicion" about the presence of encrypted data.  Sometimes this
  applies to everybody, sometimes only when you are suspected of having
  "illicit data" (definition subject to change) and sometimes specifically
  when crossing a border.  Note that this is going on in countries like
  the US and the UK to different degrees and sometimes with courts
  restricting what the authorities can actually demand.

  My advice is to either be ready to give up the keys or to not have
  encrypted data when traveling to those countries, especially when
  crossing the borders.  The latter also means not having any high-entropy
  (random) data areas on your disk, unless you can explain them and
  demonstrate that explanation.  Hence doing a zero-wipe of all free
  space, including unused space, may be a good idea.

  Disadvantages are that you do not have all the nice features that the
  LUKS metadata offers, like multiple passphrases that can be changed, the
  cipher being stored in the metadata, anti-forensic properties like
  key-slot diffusion and salts, etc..

  LUKS format uses a metadata header and 8 key-slot areas that are being
  placed at the beginning of the disk, see below under "What does the LUKS
  on-disk format looks like?".  The passphrases are used to decrypt a
  single volume key that is stored in the anti-forensic stripes.  LUKS2
  adds some more flexibility.

  Advantages are a higher usability, automatic configuration of
  non-default crypto parameters, defenses against low-entropy passphrases
  like salting and iterated PBKDF2 or ARGON 2 passphrase hashing, the
  ability to change passphrases, and others.

  Disadvantages are that it is readily obvious there is encrypted data on
  disk (but see side note above) and that damage to the header or
  key-slots usually results in permanent data-loss.  See below under "6. 
  Backup and Data Recovery" on how to reduce that risk.  Also the sector
  numbers get shifted by the length of the header and key-slots and there
  is a loss of that size in capacity.  Unless you have a specific need,
  use LUKS2.


  * **2.5 Can I encrypt an existing, non-empty partition to use LUKS?**

  There is no converter, and it is not really needed.  The way to do this
  is to make a backup of the device in question, securely wipe the device
  (as LUKS device initialization does not clear away old data), do a
  luksFormat, optionally overwrite the encrypted device, create a new
  filesystem and restore your backup on the now encrypted device.  Also
  refer to sections "Security Aspects" and "Backup and Data Recovery".

  For backup, plain GNU tar works well and backs up anything likely to be
  in a filesystem.


  * **2.6 How do I use LUKS with a loop-device?**

  This can be very handy for experiments.  Setup is just the same as with
  any block device.  If you want, for example, to use a 100MiB file as
  LUKS container, do something like this:
```
    head -c 100M /dev/zero > luksfile               # create empty file
    losetup /dev/loop0 luksfile                     # map file to /dev/loop0
    cryptsetup luksFormat --type luks2 /dev/loop0   # create LUKS2 container
```
  Afterwards just use /dev/loop0 as a you would use a LUKS partition.
  To unmap the file when done, use "losetup -d /dev/loop0".


  * **2.7 When I add a new key-slot to LUKS, it asks for a passphrase but then complains about there not being a key-slot with that passphrase?**

  That is as intended.  You are asked a passphrase of an existing key-slot
  first, before you can enter the passphrase for the new key-slot. 
  Otherwise you could break the encryption by just adding a new key-slot. 
  This way, you have to know the passphrase of one of the already
  configured key-slots in order to be able to configure a new key-slot.


  * **2.8 Encryption on top of RAID or the other way round?**

  Also see Item 2.2.  
  Unless you have special needs, place encryption between RAID and
  filesystem, i.e.  encryption on top of RAID.  You can do it the other
  way round, but you have to be aware that you then need to give the
  passphrase for each individual disk and RAID auto-detection will not
  work anymore.  Therefore it is better to encrypt the RAID device, e.g. 
  /dev/dm0 .

  This means that the typical layering looks like this:
```
  Filesystem     <- top
  |
  Encryption (LUKS)
  |
  RAID
  |
  Raw partitions (optional)
  |
  Raw disks      <- bottom
```
  The big advantage of this is that you can manage the RAID container just
  like any other regular RAID container, it does not care that its content
  is encrypted.  This strongly cuts down on complexity, something very
  valuable with storage encryption.

  Try to avoid so-called fake RAID (RAID configured from BIOS but handled
  by proprietary drivers). Note that some fake RAID firmware automatically
  writes signature on disks if enabled. This causes corruption of LUKS
  metadata. Be sure to switch the RAID option off in BIOS if you do not
  use it.

  Another data corruption can happen if you resize (enlarge) the underlying
  device and some remnant metadata appear near the end of the resized device
  (like a secondary copy of the GPT table). You can use wipefs command to
  detect and wipe such signatures.


  * **2.9 How do I read a dm-crypt key from file?**

  Use the --key-file option, like this:
```
    cryptsetup create --key-file keyfile e1 /dev/loop0
```
  This will read the binary key from file, i.e.  no hashing or
  transformation will be applied to the keyfile before its bits are used
  as key.  Extra bits (beyond the length of the key) at the end are
  ignored.  Note that if you read from STDIN, the data will be hashed,
  just as a key read interactively from the terminal.  See the man-page
  sections "NOTES ON PASSPHRASE PROCESSING..." for more detail.


  * **2.10 How do I read a LUKS slot key from file?**

  What you really do here is to read a passphrase from file, just as you
  would with manual entry of a passphrase for a key-slot.  You can add a
  new passphrase to a free key-slot, set the passphrase of an specific
  key-slot or put an already configured passphrase into a file.  Make sure
  no trailing newline (0x0a) is contained in the input key file, or the
  passphrase will not work because the whole file is used as input.

  To add a new passphrase to a free key slot from file, use something
  like this:
```
    cryptsetup luksAddKey /dev/loop0 keyfile
```   
  To add a new passphrase to a specific key-slot, use something
  like this:
```
    cryptsetup luksAddKey --key-slot 7 /dev/loop0 keyfile
```   
  To supply a key from file to any LUKS command, use the --key-file
  option, e.g. like this:
```
    cryptsetup luksOpen --key-file keyfile /dev/loop0 e1
```   


  * **2.11 How do I read the LUKS volume key from file?**

  The question you should ask yourself first is why you would want to do
  this.  The only legitimate reason I can think of is if you want to have
  two LUKS devices with the same volume key.  Even then, I think it would
  be preferable to just use key-slots with the same passphrase, or to use
  plain dm-crypt instead.

  Use the --volume-key-file option, like this:
```
    cryptsetup luksFormat --volume-key-file keyfile /dev/loop0
```

  * **2.12 What are the security requirements for a key read from file?**

  A file-stored key or passphrase has the same security requirements as
  one entered interactively, however you can use random bytes and thereby
  use bytes you cannot type on the keyboard.  You can use any file you
  like as key file, for example a plain text file with a human readable
  passphrase.  To generate a file with random bytes, use something like
  this:
```
    head -c 256 /dev/random > keyfile
```


  * **2.13 If I map a journaled file system using dm-crypt/LUKS, does it still provide its usual transactional guarantees?**

  Yes, it does, unless a very old kernel is used.  The required flags come
  from the filesystem layer and are processed and passed onward by
  dm-crypt (regardless of direct key management or LUKS key management). 
  A bit more information on the process by which transactional guarantees
  are implemented can be found here:

  https://lwn.net/Articles/400541/

  Please note that these "guarantees" are weaker than they appear to be. 
  One problem is that quite a few disks lie to the OS about having flushed
  their buffers.  This is likely still true with SSDs.  Some other things
  can go wrong as well.  The filesystem developers are aware of these
  problems and typically can make it work anyways.  That said,
  dm-crypt/LUKS will not make things worse.

  One specific problem you can run into is that you can get short freezes
  and other slowdowns due to the encryption layer.  Encryption takes time
  and forced flushes will block for that time.  For example, I did run
  into frequent small freezes (1-2 sec) when putting a vmware image on
  ext3 over dm-crypt.  When I went back to ext2, the problem went away. 
  This seems to have gotten better with kernel 2.6.36 and the reworking of
  filesystem flush locking mechanism (less blocking of CPU activity during
  flushes).  This should improve further and eventually the problem should
  go away.


  * **2.14 Can I use LUKS or cryptsetup with a more secure (external) medium for key storage, e.g. TPM or a smartcard?**

  Yes, see the answers on using a file-supplied key.  You do have to write
  the glue-logic yourself though.  Basically you can have cryptsetup read
  the key from STDIN and write it there with your own tool that in turn
  gets the key from the more secure key storage.


  * **2.15 Can I resize a dm-crypt or LUKS container?**

  Yes, you can, as neither dm-crypt nor LUKS1 stores partition size and
  LUKS2 uses a generic "whole device" size as default.  Note that LUKS2
  can use specified data-area sizes as a non-standard case and that these
  may cause issues when resizing a LUKS2 container if set to a specific
  value.

  Whether you should do this is a different question.  Personally I
  recommend backup, recreation of the dm-crypt or LUKS container with new
  size, recreation of the filesystem and restore.  This gets around the
  tricky business of resizing the filesystem.  Resizing a dm-crypt or LUKS
  container does not resize the filesystem in it.  A backup is really
  non-optional here, as a lot can go wrong, resulting in partial or
  complete data loss.  But if you have that backup, you can also just
  recreate everything.

  You also need to be aware of size-based limitations.  The one currently
  relevant is that aes-xts-plain should not be used for encrypted
  container sizes larger than 2TiB.  Use aes-xts-plain64 for that.


  * **2.16 How do I Benchmark the Ciphers, Hashes and Modes?**

  Since version 1.60 cryptsetup supports the "benchmark" command. 
  Simply run as root:
```
    cryptsetup benchmark
```
  You can get more than the default benchmarks, see the man-page for the
  relevant parameters.  Note that XTS mode takes two keys, hence the
  listed key sizes are double that for other modes and half of it is the
  cipher key, the other half is the XTS key.


  * **2.17 How do I Verify I have an Authentic cryptsetup Source Package?**

  Current maintainer is Milan Broz and he signs the release packages with
  his PGP key.  The key he currently uses is the "RSA key ID D93E98FC",
  fingerprint 2A29 1824 3FDE 4664 8D06 86F9 D9B0 577B D93E 98FC.  While I
  have every confidence this really is his key and that he is who he
  claims to be, don't depend on it if your life is at stake.  For that
  matter, if your life is at stake, don't depend on me being who I claim
  to be either.

  That said, as cryptsetup is under good version control and a malicious
  change should be noticed sooner or later, but it may take a while. 
  Also, the attacker model makes compromising the sources in a non-obvious
  way pretty hard.  Sure, you could put the volume-key somewhere on disk,
  but that is rather obvious as soon as somebody looks as there would be
  data in an empty LUKS container in a place it should not be.  Doing this
  in a more nefarious way, for example hiding the volume-key in the salts,
  would need a look at the sources to be discovered, but I think that
  somebody would find that sooner or later as well.

  That said, this discussion is really a lot more complicated and longer
  as an FAQ can sustain.  If in doubt, ask on the mailing list.


  * **2.18 Is there a concern with 4k Sectors?**

  Not from dm-crypt itself.  Encryption will be done in 512B blocks, but
  if the partition and filesystem are aligned correctly and the filesystem
  uses multiples of 4kiB as block size, the dm-crypt layer will just
  process 8 x 512B = 4096B at a time with negligible overhead.  LUKS does
  place data at an offset, which is 2MiB per default and will not break
  alignment.  See also Item 6.12 of this FAQ for more details.  Note that
  if your partition or filesystem is misaligned, dm-crypt can make the
  effect worse though.  Also note that SSDs typically have much larger
  blocks internally (e.g.  128kB or even larger).


  * **2.19 How can I wipe a device with crypto-grade randomness?**

  The conventional recommendation if you want to do more than just a
  zero-wipe is to use something like
```
    cat /dev/urandom >  <target-device>
```
  That used to very slow and painful at 10-20MB/s on a fast computer, but
  newer kernels can give you > 200MB/s (depending on hardware).  An
  alternative is using cryptsetup and a plain dm-crypt device with a
  random key, which is fast and on the same level of security.  The
  defaults are quite enough.

  For device set-up, do the following:
```
    cryptsetup open --type plain -d /dev/urandom /dev/<device> target
```
  This maps the container as plain under /dev/mapper/target with a random
  password.  For the actual wipe you have several options.  Basically, you
  pipe zeroes into the opened container that then get encrypted.  Simple
  wipe without progress-indicator:
```
    cat /dev/zero > /dev/mapper/to_be_wiped
```
  Progress-indicator by dd_rescue:
```
    dd_rescue -w /dev/zero /dev/mapper/to_be_wiped
```
  Progress-indicator by my "wcs" stream meter (available from
  https://www.tansi.org/tools/index.html ):
```
    cat /dev/zero | wcs > /dev/mapper/to_be_wiped
```
  Or use plain "dd", which gives you the progress when sent a SIGUSR1, see
  the dd man page. The GNU "dd" command supports the "status=progress"
  operand that gives you the progress without having to send it any signal.

  Remove the mapping at the end and you are done.


  * **2.20 How do I wipe only the LUKS header?**
 
  This does _not_ describe an emergency wipe procedure, see Item 5.4 for
  that.  This procedure here is intended to be used when the data should
  stay intact, e.g.  when you change your LUKS container to use a detached
  header and want to remove the old one.  Please only do this if you have
  a current backup.

  LUKS1:  
  01) Determine header size in 512 Byte sectors with luksDump:
```
     cryptsetup luksDump <device with LUKS container>

->   ...
     Payload offset: <number> [of 512 byte sectors]
     ...
```
  02) Take the result number, multiply by 512 zeros and write to 
      the start of the device, e.g. using one of the following alternatives:
```
     dd bs=512 count=<number> if=/dev/zero of=<device>
```        
```  
     head -c <number * 512> /dev/zero > /dev/<device>
```

  LUKS2:  
  (warning, untested!  Remember that backup?) This assumes the
  LUKS2 container uses the defaults, in particular there is only one data
  segment.  
  01) Determine the data-segment offset using luksDump, same
      as above for LUKS1:
```
     cryptsetup luksDump <device with LUKS container>
->   ...  
     Data segments:
        0: crypt
           offset: <number> [bytes]
     ...
```
  02) Overwrite the stated number of bytes from the start of the device.
      Just to give yet another way to get a defined number of zeros:
```
     head -c <number> /dev/zero > /dev/<device>
```

# 3. Common Problems


  * **3.1 My dm-crypt/LUKS mapping does not work! What general steps are there to investigate the problem?**

  If you get a specific error message, investigate what it claims first. 
  If not, you may want to check the following things.

  - Check that "/dev", including "/dev/mapper/control" is there.  If it is
  missing, you may have a problem with the "/dev" tree itself or you may
  have broken udev rules.

  - Check that you have the device mapper and the crypt target in your
  kernel.  The output of "dmsetup targets" should list a "crypt" target. 
  If it is not there or the command fails, add device mapper and
  crypt-target to the kernel.

  - Check that the hash-functions and ciphers you want to use are in the
  kernel.  The output of "cat /proc/crypto" needs to list them.


  * **3.2 My dm-crypt mapping suddenly stopped when upgrading cryptsetup.**

  The default cipher, hash or mode may have changed (the mode changed from
  1.0.x to 1.1.x).  See under "Issues With Specific Versions of
  cryptsetup".


  * **3.3 When I call cryptsetup from cron/CGI, I get errors about unknown features?**

  If you get errors about unknown parameters or the like that are not
  present when cryptsetup is called from the shell, make sure you have no
  older version of cryptsetup on your system that then gets called by
  cron/CGI.  For example some distributions install cryptsetup into
  /usr/sbin, while a manual install could go to /usr/local/sbin.  As a
  debugging aid, call "cryptsetup --version" from cron/CGI or the
  non-shell mechanism to be sure the right version gets called.


  * **3.4 Unlocking a LUKS device takes very long. Why?**

  The unlock time for a key-slot (see Section 5 for an explanation what
  iteration does) is calculated when setting a passphrase.  By default it
  is 1 second (2 seconds for LUKS2).  If you set a passphrase on a fast
  machine and then unlock it on a slow machine, the unlocking time can be
  much longer.  Also take into account that up to 8 key-slots (LUKS2: up
  to 32 key-slots) have to be tried in order to find the right one.

  If this is the problem, you can add another key-slot using the slow
  machine with the same passphrase and then remove the old key-slot.  The
  new key-slot will have the unlock time adjusted to the slow machine.
  Use luksKeyAdd and then luksKillSlot or luksRemoveKey.  You can also use
  the -i option to reduce iteration time (and security level) when setting 
  a passphrase.  Default is 1000 (1 sec) for LUKS1 and 2000 (2sec) for
  LUKS2.

  However, this operation will not change volume key iteration count ("MK
  iterations" for LUKS1, "Iterations" under "Digests" for LUKS2).  In
  order to change that, you will have to backup the data in the LUKS
  container (i.e.  your encrypted data), luksFormat on the slow machine
  and restore the data.  Note that MK iterations are not very security
  relevant.


  * **3.5 "blkid" sees a LUKS UUID and an ext2/swap UUID on the same device. What is wrong?**

  Some old versions of cryptsetup have a bug where the header does not get
  completely wiped during LUKS format and an older ext2/swap signature
  remains on the device.  This confuses blkid.

  Fix: Wipe the unused header areas by doing a backup and restore of
  the header with cryptsetup 1.1.x or later:
```
    cryptsetup luksHeaderBackup --header-backup-file <file> <device>
    cryptsetup luksHeaderRestore --header-backup-file <file> <device>
```

  * **3.6 I see a data corruption with the Intel QAT kernel driver; why?**

  Intel QAT crypto API drivers have severe bugs that are not fixed for years.

  If you see data corruption, please disable the QAT in the BIOS or avoid loading
  kernel Intel QAT drivers (switch to software crypto implementation or AES-NI).

  For more info, see posts in dm-devel list https://lore.kernel.org/dm-devel/?q=intel+qat


# 4. Troubleshooting


  * **4.1 I get the error "LUKS keyslot x is invalid." What does that mean?**

  For LUKS1, this means that the given keyslot has an offset that points
  outside the valid keyslot area.  Typically, the reason is a corrupted
  LUKS1 header because something was written to the start of the device
  the LUKS1 container is on.  For LUKS2, I do not know when this error can
  happen, but I expect it will be something similar.  Refer to Section
  "Backup and Data Recovery" and ask on the mailing list if you have
  trouble diagnosing and (if still possible) repairing this.


  * **4.2 I cannot unlock my LUKS container! What could be the problem?**

  First, make sure you have a correct passphrase.  Then make sure you have
  the correct key-map and correct keyboard.  And then make sure you have
  the correct character set and encoding, see also "PASSPHRASE CHARACTER
  SET" under Section 1.2.

  If you are sure you are entering the passphrase right, there is the
  possibility that the respective key-slot has been damaged.  There is no
  way to recover a damaged key-slot, except from a header backup (see
  Section 6).  For security reasons, there is also no checksum in the
  key-slots that could tell you whether a key-slot has been damaged.  The
  only checksum present allows recognition of a correct passphrase, but
  that only works with that correct passphrase and a respective key-slot
  that is intact.

  In order to find out whether a key-slot is damaged one has to look for
  "non-random looking" data in it.  There is a tool that automates this
  for LUKS1 in the cryptsetup distribution from version 1.6.0 onwards.  It
  is located in misc/keyslot_checker/.  Instructions how to use and how to
  interpret results are in the README file.  Note that this tool requires
  a libcryptsetup from cryptsetup 1.6.0 or later (which means
  libcryptsetup.so.4.5.0 or later).  If the tool complains about missing
  functions in libcryptsetup, you likely have an earlier version from your
  distribution still installed.  You can either point the symbolic link(s)
  from libcryptsetup.so.4 to the new version manually, or you can
  uninstall the distribution version of cryptsetup and re-install that
  from cryptsetup >= 1.6.0 again to fix this.


  * **4.3 Can a bad RAM module cause problems?**

  LUKS and dm-crypt can give the RAM quite a workout, especially when
  combined with software RAID.  In particular the combination RAID5 +
  LUKS1 + XFS seems to uncover RAM problems that do not cause obvious
  problems otherwise.  Symptoms vary, but often the problem manifests
  itself when copying large amounts of data, typically several times
  larger than your main memory.

  Note: One thing you should always do on large data copying or movements
  is to run a verify, for example with the "-d" option of "tar" or by
  doing a set of MD5 checksums on the source or target with
```
    find . -type f -exec md5sum \{\} \; > checksum-file
```
  and then a "md5sum -c checksum-file" on the other side.  If you get
  mismatches here, RAM is the primary suspect.  A lesser suspect is an
  overclocked CPU.  I have found countless hardware problems in verify
  runs after copying data or making backups.  Bit errors are much more
  common than most people think.

  Some RAM issues are even worse and corrupt structures in one of the
  layers.  This typically results in lockups, CPU state dumps in the
  system logs, kernel panic or other things.  It is quite possible to have
  a problem with an encrypted device, but not with an otherwise the same
  unencrypted device.  The reason for that is that encryption has an error
  amplification property: If you flip one bit in an encrypted data block,
  the decrypted version has half of its bits flipped.  This is actually an
  important security property for modern ciphers.  With the usual modes in
  cryptsetup (CBC, ESSIV, XTS), you can get a completely changed 512 byte
  block for a bit error.  A corrupt block causes a lot more havoc than the
  occasionally flipped single bit and can result in various obscure
  errors.

  Note that a verify run on copying between encrypted or unencrypted
  devices will reliably detect corruption, even when the copying itself
  did not report any problems.  If you find defect RAM, assume all backups
  and copied data to be suspect, unless you did a verify.


  * **4.4 How do I test RAM?**

  First you should know that overclocking often makes memory problems
  worse.  So if you overclock (which I strongly recommend against in a
  system holding data that has any worth), run the tests with the
  overclocking active.

  There are two good options.  One is Memtest86+ and the other is
  "memtester" by Charles Cazabon.  Memtest86+ requires a reboot and then
  takes over the machine, while memtester runs from a root-shell.  Both
  use different testing methods and I have found problems fast with either
  one that the other needed long to find.  I recommend running the
  following procedure until the first error is found:

  - Run Memtest86+ for one cycle

  - Run memtester for one cycle (shut down as many other applications
    as possible and use the largest memory area you can get)

  - Run Memtest86+ for 24h or more

  - Run memtester for 24h or more

  If all that does not produce error messages, your RAM may be sound,
  but I have had one weak bit in the past that Memtest86+ needed around 
  60 hours to find.  If you can reproduce the original problem reliably, 
  a good additional test may be to remove half of the RAM (if you have 
  more than one module) and try whether the problem is still there and if
  so, try with the other half.  If you just have one module, get a
  different one and try with that.  If you do overclocking, reduce the
  settings to the most conservative ones available and try with that.


  * **4.5 Is there a risk using debugging tools like strace?**

  There most definitely is. A dump from strace and friends can contain
  all data entered, including the full passphrase.  Example with strace
  and passphrase "test":
```
    > strace cryptsetup luksOpen /dev/sda10 c1
    ...
    read(6, "test\n", 512)                  = 5
    ...
```
  Depending on different factors and the tool used, the passphrase may
  also be encoded and not plainly visible.  Hence it is never a good idea
  to give such a trace from a live container to anybody.  Recreate the
  problem with a test container or set a temporary passphrase like "test"
  and use that for the trace generation.  Item 2.6 explains how to create
  a loop-file backed LUKS container that may come in handy for this
  purpose.

  See also Item 6.10 for another set of data you should not give to
  others.


# 5. Security Aspects


  * **5.1 How long is a secure passphrase?**

  This is just the short answer.  For more info and explanation of some of
  the terms used in this item, read the rest of Section 5.  The actual
  recommendation is at the end of this item.

  First, passphrase length is not really the right measure, passphrase
  entropy is.  If your passphrase is 200 times the letter "a", it is long
  but has very low entropy and is pretty insecure.

  For example, a random lowercase letter (a-z) gives you 4.7 bit of
  entropy, one element of a-z0-9 gives you 5.2 bits of entropy, an element
  of a-zA-Z0-9 gives you 5.9 bits and a-zA-Z0-9!@#$%\^&:-+ gives you 6.2
  bits.  On the other hand, a random English word only gives you 0.6...1.3
  bits of entropy per character.  Using sentences that make sense gives
  lower entropy, series of random words gives higher entropy.  Do not use
  sentences that can be tied to you or found on your computer.  This type
  of attack is done routinely today.

  That said, it does not matter too much what scheme you use, but it does
  matter how much entropy your passphrase contains, because an attacker
  has to try on average
```
    1/2 * 2^(bits of entropy in passphrase)
```
  different passphrases to guess correctly.

  Historically, estimations tended to use computing time estimates, but
  more modern approaches try to estimate cost of guessing a passphrase.

  As an example, I will try to get an estimate from the numbers in
  https://gist.github.com/epixoip/a83d38f412b4737e99bbef804a270c40 This
  thing costs 23kUSD and does 68Ghashes/sec for SHA1.  This is in 2017.
 
  Incidentally, my older calculation for a machine around 1000 times
  slower was off by a factor of about 1000, but in the right direction,
  i.e.  I estimated the attack to be too easy.  Nobody noticed ;-) On the
  plus side, the tables are now (2017) pretty much accurate.

  More references can be found at the end of this document.  Note that
  these are estimates from the defender side, so assuming something is
  easier than it actually is fine.  An attacker may still have
  significantly higher cost than estimated here.

  LUKS1 used SHA1 (since version 1.7.0 it uses SHA256) for hashing per
  default.  We will leave aside the check whether a try actually decrypts 
  a key-slot.  I will assume a useful lifetime of the hardware of 2 years. 
  (This is on the low side.) Disregarding downtime, the machine can then
  break
```
     N = 68*10^9 * 3600 * 24 * 365 * 2 ~ 4*10^18
```
  passphrases for EUR/USD 23k.  That is one 62 bit passphrase hashed once
  with SHA1 for EUR/USD 23k.  This can be parallelized, it can be done
  faster than 2 years with several of these machines.

  For LUKS2, things look a bit better, as the advantage of using graphics
  cards is massively reduced.  Using the recommendations below should
  hence be fine for LUKS2 as well and give a better security margin.

  For plain dm-crypt (no hash iteration) this is it.  This gives (with
  SHA1, plain dm-crypt default is ripemd160 which seems to be slightly
  slower than SHA1):
```
    Passphrase entropy  Cost to break
    60 bit              EUR/USD     6k
    65 bit              EUR/USD   200K
    70 bit              EUR/USD     6M
    75 bit              EUR/USD   200M
    80 bit              EUR/USD     6B
    85 bit              EUR/USD   200B
    ...                      ...
```

  For LUKS1, you have to take into account hash iteration in PBKDF2. 
  For a current CPU, there are about 100k iterations (as can be queried
  with ''cryptsetup luksDump''. 

  The table above then becomes:
```
    Passphrase entropy  Cost to break
    50 bit              EUR/USD   600k
    55 bit              EUR/USD    20M
    60 bit              EUR/USD   600M
    65 bit              EUR/USD    20B
    70 bit              EUR/USD   600B
    75 bit              EUR/USD    20T
    ...                      ...
```

  Recommendation:

  To get reasonable security for the  next 10 years, it is a good idea
  to overestimate by a factor of at least 1000.

  Then there is the question of how much the attacker is willing to spend. 
  That is up to your own security evaluation.  For general use, I will
  assume the attacker is willing to spend up to 1 million EUR/USD.  Then
  we get the following recommendations:

  Plain dm-crypt: Use > 80 bit. That is e.g. 17 random chars from a-z
  or a random English sentence of > 135 characters length.

  LUKS1 and LUKS2: Use > 65 bit. That is e.g. 14 random chars from a-z 
  or a random English sentence of > 108 characters length.

  If paranoid, add at least 20 bit. That is roughly four additional
  characters for random passphrases and roughly 32 characters for a
  random English sentence. 


  * **5.2 Is LUKS insecure? Everybody can see I have encrypted data!**

  In practice it does not really matter.  In most civilized countries you
  can just refuse to hand over the keys, no harm done.  In some countries
  they can force you to hand over the keys if they suspect encryption. 
  The suspicion is enough, they do not have to prove anything.  This is
  for practical reasons, as even the presence of a header (like the LUKS
  header) is not enough to prove that you have any keys.  It might have
  been an experiment, for example.  Or it was used as encrypted swap with
  a key from /dev/random.  So they make you prove you do not have
  encrypted data.  Of course, if true, that is impossible and hence the
  whole idea is not compatible with fair laws.  Note that in this context,
  countries like the US or the UK are not civilized and do not have fair
  laws.

  As a side-note, standards for biometrics (fingerprint, retina, 
  vein-pattern, etc.) are often different and much lower. If you put
  your LUKS passphrase into a device that can be unlocked using biometrics,
  they may force a biometric sample in many countries where they could not
  force you to give them a passphrase you solely have in your memory and
  can claim to have forgotten if needed (it happens). If you need protection
  on this level, make sure you know what the respective legal situation is,
  also while traveling, and make sure you decide beforehand what you
  will do if push comes to shove as they will definitely put you under
  as much pressure as they can legally apply. 

  This means that if you have a large set of random-looking data, they can
  already lock you up.  Hidden containers (encryption hidden within
  encryption), as possible with Truecrypt, do not help either.  They will
  just assume the hidden container is there and unless you hand over the
  key, you will stay locked up.  Don't have a hidden container?  Tough
  luck.  Anybody could claim that.

  Still, if you are concerned about the LUKS header, use plain dm-crypt
  with a good passphrase.  See also Section 2, "What is the difference
  between "plain" and LUKS format?"


  * **5.3 Should I initialize (overwrite) a new LUKS/dm-crypt partition?**

  If you just create a filesystem on it, most of the old data will still
  be there.  If the old data is sensitive, you should overwrite it before
  encrypting.  In any case, not initializing will leave the old data there
  until the specific sector gets written.  That may enable an attacker to
  determine how much and where on the partition data was written.  If you
  think this is a risk, you can prevent this by overwriting the encrypted
  device (here assumed to be named "e1") with zeros like this:
```
    dd_rescue -w /dev/zero /dev/mapper/e1
```
  or alternatively with one of the following more standard commands:
```
    cat /dev/zero > /dev/mapper/e1
    dd if=/dev/zero of=/dev/mapper/e1
```


  * **5.4 How do I securely erase a LUKS container?**

  For LUKS, if you are in a desperate hurry, overwrite the LUKS header and
  key-slot area.  For LUKS1 and LUKS2, just be generous and overwrite the
  first 100MB.  A single overwrite with zeros should be enough.  If you
  anticipate being in a desperate hurry, prepare the command beforehand. 
  Example with /dev/sde1 as the LUKS partition and default parameters:
```
    head -c 100000000 /dev/zero > /dev/sde1; sync
```
  A LUKS header backup or full backup will still grant access to most or
  all data, so make sure that an attacker does not have access to backups
  or destroy them as well.

  Also note that SSDs and also some HDDs (SMR and hybrid HDDs, for
  example) may not actually overwrite the header and only do that an
  unspecified and possibly very long time later.  The only way to be sure
  there is physical destruction.  If the situation permits, do both
  overwrite and physical destruction.

  If you have time, overwrite the whole drive with a single pass of random
  data.  This is enough for most HDDs.  For SSDs or FLASH (USB sticks) or
  SMR or hybrid drives, you may want to overwrite the whole drive several
  times to be sure data is not retained.  This is possibly still insecure
  as the respective technologies are not fully understood in this regard. 
  Still, due to the anti-forensic properties of the LUKS key-slots, a
  single overwrite could be enough.  If in doubt, use physical destruction
  in addition.  Here is a link to some current research results on erasing
  SSDs and FLASH drives:
  https://www.usenix.org/events/fast11/tech/full_papers/Wei.pdf

  Keep in mind to also erase all backups.

  Example for a random-overwrite erase of partition sde1 done with
  dd_rescue:
```
    dd_rescue -w /dev/urandom /dev/sde1
```


  * **5.5 How do I securely erase a backup of a LUKS partition or header?**

  That depends on the medium it is stored on.  For HDD and SSD, use
  overwrite with random data.  For an SSD, FLASH drive (USB stick) hybrid
  HDD or SMR HDD, you may want to overwrite the complete drive several
  times and use physical destruction in addition, see last item.  For
  re-writable CD/DVD, a single overwrite should be enough, due to the
  anti-forensic properties of the LUKS keyslots.  For write-once media,
  use physical destruction.  For low security requirements, just cut the
  CD/DVD into several parts.  For high security needs, shred or burn the
  medium.

  If your backup is on magnetic tape, I advise physical destruction by
  shredding or burning, after (!) overwriting.  The problem with magnetic
  tape is that it has a higher dynamic range than HDDs and older data may
  well be recoverable after overwrites.  Also write-head alignment issues
  can lead to data not actually being deleted during overwrites.

  The best option is to actually encrypt the backup, for example with
  PGP/GnuPG and then just destroy all copies of the encryption key if
  needed.  Best keep them on paper, as that has excellent durability and
  secure destruction is easy, for example by burning and then crushing the
  ashes to a fine powder.  A blender and water also works nicely.


  * **5.6 What about backup? Does it compromise security?**

  That depends. See item 6.7.


  * **5.7 Why is all my data permanently gone if I overwrite the LUKS header?**

  Overwriting the LUKS header in part or in full is the most common reason
  why access to LUKS containers is lost permanently.  Overwriting can be
  done in a number of fashions, like creating a new filesystem on the raw
  LUKS partition, making the raw partition part of a RAID array and just
  writing to the raw partition.

  The LUKS1 header contains a 256 bit "salt" per key-slot and without that
  no decryption is possible.  While the salts are not secret, they are
  key-grade material and cannot be reconstructed.  This is a
  cryptographically strong "cannot".  From observations on the cryptsetup
  mailing-list, people typically go though the usual stages of grief
  (Denial, Anger, Bargaining, Depression, Acceptance) when this happens to
  them.  Observed times vary between 1 day and 2 weeks to complete the
  cycle.  Seeking help on the mailing-list is fine.  Even if we usually
  cannot help with getting back your data, most people found the feedback
  comforting.

  If your header does not contain an intact key-slot salt, best go
  directly to the last stage ("Acceptance") and think about what to do
  now.  There is one exception that I know of: If your LUKS1 container is
  still open, then it may be possible to extract the volume key from the
  running system.  See Item "How do I recover the volume key from a mapped
  LUKS1 container?" in Section "Backup and Data Recovery".

  For LUKS2, things are both better and worse.  First, the salts are in a
  less vulnerable position now.  But, on the other hand, the keys of a
  mapped (open) container are now stored in the kernel key-store, and
  while there probably is some way to get them out of there, I am not sure
  how much effort that needs.


  * **5.8 What is a "salt"?**

  A salt is a random key-grade value added to the passphrase before it is
  processed.  It is not kept secret.  The reason for using salts is as
  follows: If an attacker wants to crack the password for a single LUKS
  container, then every possible passphrase has to be tried.  Typically an
  attacker will not try every binary value, but will try words and
  sentences from a dictionary.

  If an attacker wants to attack several LUKS containers with the same
  dictionary, then a different approach makes sense: Compute the resulting
  slot-key for each dictionary element and store it on disk.  Then the
  test for each entry is just the slow unlocking with the slot key (say
  0.00001 sec) instead of calculating the slot-key first (1 sec).  For a
  single attack, this does not help.  But if you have more than one
  container to attack, this helps tremendously, also because you can
  prepare your table before you even have the container to attack!  The
  calculation is also very simple to parallelize.  You could, for example,
  use the night-time unused CPU power of your desktop PCs for this.

  This is where the salt comes in.  If the salt is combined with the
  passphrase (in the simplest form, just appended to it), you suddenly
  need a separate table for each salt value.  With a reasonably-sized salt
  value (256 bit, e.g.) this is quite infeasible.


  * **5.9 Is LUKS secure with a low-entropy (bad) passphrase?**

  Short answer: yes. Do not use a low-entropy passphrase.

  Note: For LUKS2, protection for bad passphrases is a bit better
  due to the use of Argon2, but that is only a gradual improvement.

  Longer answer:  
  This needs a bit of theory.  The quality of your passphrase is directly
  related to its entropy (information theoretic, not thermodynamic).  The
  entropy says how many bits of "uncertainty" or "randomness" are in you
  passphrase.  In other words, that is how difficult guessing the
  passphrase is.

  Example: A random English sentence has about 1 bit of entropy per
  character.  A random lowercase (or uppercase) character has about 4.7
  bit of entropy.

  Now, if n is the number of bits of entropy in your passphrase and t
  is the time it takes to process a passphrase in order to open the
  LUKS container, then an attacker has to spend at maximum
```
    attack_time_max = 2^n * t
```
  time for a successful attack and on average half that.  There is no way
  getting around that relationship.  However, there is one thing that does
  help, namely increasing t, the time it takes to use a passphrase, see
  next FAQ item.

  Still, if you want good security, a high-entropy passphrase is the only
  option.  For example, a low-entropy passphrase can never be considered
  secure against a TLA-level (Three Letter Agency level, i.e. 
  government-level) attacker, no matter what tricks are used in the
  key-derivation function.  Use at least 64 bits for secret stuff.  That
  is 64 characters of English text (but only if randomly chosen) or a
  combination of 12 truly random letters and digits.

  For passphrase generation, do not use lines from very well-known texts
  (religious texts, Harry Potter, etc.) as they are too easy to guess.
  For example, the total Harry Potter has about 1'500'000 words (my
  estimation).  Trying every 64 character sequence starting and ending at
  a word boundary would take only something like 20 days on a single CPU
  and is entirely feasible.  To put that into perspective, using a number
  of Amazon EC2 High-CPU Extra Large instances (each gives about 8 real
  cores), this test costs currently about 50USD/EUR, but can be made to
  run arbitrarily fast.

  On the other hand, choosing 1.5 lines from, say, the Wheel of Time, is
  in itself not more secure, but the book selection adds quite a bit of
  entropy.  (Now that I have mentioned it here, don't use tWoT either!) If
  you add 2 or 3 typos and switch some words around, then this is good
  passphrase material.


  * **5.10 What is "iteration count" and why is decreasing it a bad idea?**

  LUKS1:  
  Iteration count is the number of PBKDF2 iterations a passphrase is put
  through before it is used to unlock a key-slot.  Iterations are done
  with the explicit purpose to increase the time that it takes to unlock a
  key-slot.  This provides some protection against use of low-entropy
  passphrases.

  The idea is that an attacker has to try all possible passphrases.  Even
  if the attacker knows the passphrase is low-entropy (see last item), it
  is possible to make each individual try take longer.  The way to do this
  is to repeatedly hash the passphrase for a certain time.  The attacker
  then has to spend the same time (given the same computing power) as the
  user per try.  With LUKS1, the default is 1 second of PBKDF2 hashing.

  Example 1: Lets assume we have a really bad passphrase (e.g.  a
  girlfriends name) with 10 bits of entropy.  With the same CPU, an
  attacker would need to spend around 500 seconds on average to break that
  passphrase.  Without iteration, it would be more like 0.0001 seconds on
  a modern CPU.

  Example 2: The user did a bit better and has 32 chars of English text. 
  That would be about 32 bits of entropy.  With 1 second iteration, that
  means an attacker on the same CPU needs around 136 years.  That is
  pretty impressive for such a weak passphrase.  Without the iterations,
  it would be more like 50 days on a modern CPU, and possibly far less.

  In addition, the attacker can both parallelize and use special hardware
  like GPUs or FPGAs to speed up the attack.  The attack can also happen
  quite some time after the luksFormat operation and CPUs can have become
  faster and cheaper.  For that reason you want a bit of extra security. 
  Anyways, in Example 1 your are screwed.  In example 2, not necessarily. 
  Even if the attack is faster, it still has a certain cost associated
  with it, say 10000 EUR/USD with iteration and 1 EUR/USD without
  iteration.  The first can be prohibitively expensive, while the second
  is something you try even without solid proof that the decryption will
  yield something useful.

  The numbers above are mostly made up, but show the idea.  Of course the
  best thing is to have a high-entropy passphrase.

  Would a 100 sec iteration time be even better?  Yes and no. 
  Cryptographically it would be a lot better, namely 100 times better. 
  However, usability is a very important factor for security technology
  and one that gets overlooked surprisingly often.  For LUKS, if you have
  to wait 2 minutes to unlock the LUKS container, most people will not
  bother and use less secure storage instead.  It is better to have less
  protection against low-entropy passphrases and people actually use LUKS,
  than having them do without encryption altogether.

  Now, what about decreasing the iteration time?  This is generally a very
  bad idea, unless you know and can enforce that the users only use
  high-entropy passphrases.  If you decrease the iteration time without
  ensuring that, then you put your users at increased risk, and
  considering how rarely LUKS containers are unlocked in a typical
  work-flow, you do so without a good reason.  Don't do it.  The iteration
  time is already low enough that users with low entropy passphrases are
  vulnerable.  Lowering it even further increases this danger
  significantly.

  LUKS2: Pretty much the same reasoning applies. The advantages of using
  GPUs or FPGAs in an attack have been significantly reduced, but that 
  is the only main difference.


  * **5.11 Some people say PBKDF2 is insecure?**

  There is some discussion that a hash-function should have a "large
  memory" property, i.e.  that it should require a lot of memory to be
  computed.  This serves to prevent attacks using special programmable
  circuits, like FPGAs, and attacks using graphics cards.  PBKDF2 does not
  need a lot of memory and is vulnerable to these attacks.  However, the
  publication usually referred in these discussions is not very convincing
  in proving that the presented hash really is "large memory" (that may
  change, email the FAQ maintainer when it does) and it is of limited
  usefulness anyways.  Attackers that use clusters of normal PCs will not
  be affected at all by a "large memory" property.  For example the US
  Secret Service is known to use the off-hour time of all the office PCs
  of the Treasury for password breaking.  The Treasury has about 110'000
  employees.  Assuming every one has an office PC, that is significant
  computing power, all of it with plenty of memory for computing "large
  memory" hashes.  Bot-net operators also have all the memory they want. 
  The only protection against a resourceful attacker is a high-entropy
  passphrase, see items 5.9 and 5.10.

  That said, LUKS2 defaults to Argon2, which has a large-memory property
  and massively reduces the advantages of GPUs and FPGAs.


  * **5.12 What about iteration count with plain dm-crypt?**

  Simple: There is none.  There is also no salting.  If you use plain
  dm-crypt, the only way to be secure is to use a high entropy passphrase. 
  If in doubt, use LUKS instead.


  * **5.13 Is LUKS with default parameters less secure on a slow CPU?**

  Unfortunately, yes.  However the only aspect affected is the protection
  for low-entropy passphrase or volume-key.  All other security aspects
  are independent of CPU speed.

  The volume key is less critical, as you really have to work at it to
  give it low entropy.  One possibility to mess this up is to supply the
  volume key yourself.  If that key is low-entropy, then you get what you
  deserve.  The other known possibility to create a LUKS container with a
  bad volume key is to use /dev/urandom for key generation in an
  entropy-starved situation (e.g.  automatic installation on an embedded
  device without network and other entropy sources or installation in a VM
  under certain circumstances).

  For the passphrase, don't use a low-entropy passphrase.  If your
  passphrase is good, then a slow CPU will not matter.  If you insist on a
  low-entropy passphrase on a slow CPU, use something like
  "--iter-time=10000" or higher and wait a long time on each LUKS unlock
  and pray that the attacker does not find out in which way exactly your
  passphrase is low entropy.  This also applies to low-entropy passphrases
  on fast CPUs.  Technology can do only so much to compensate for problems
  in front of the keyboard.

  Also note that power-saving modes will make your CPU slower.  This will
  reduce iteration count on LUKS container creation.  It will keep unlock
  times at the expected values though at this CPU speed.


  * **5.14 Why was the default aes-cbc-plain replaced with aes-cbc-essiv?**

  Note: This item applies both to plain dm-crypt and to LUKS

  The problem is that cbc-plain has a fingerprint vulnerability, where a
  specially crafted file placed into the crypto-container can be
  recognized from the outside.  The issue here is that for cbc-plain the
  initialization vector (IV) is the sector number.  The IV gets XORed to
  the first data chunk of the sector to be encrypted.  If you make sure
  that the first data block to be stored in a sector contains the sector
  number as well, the first data block to be encrypted is all zeros and
  always encrypted to the same ciphertext.  This also works if the first
  data chunk just has a constant XOR with the sector number.  By having
  several shifted patterns you can take care of the case of a
  non-power-of-two start sector number of the file.

  This mechanism allows you to create a pattern of sectors that have the
  same first ciphertext block and signal one bit per sector to the
  outside, allowing you to e.g.  mark media files that way for recognition
  without decryption.  For large files this is a practical attack.  For
  small ones, you do not have enough blocks to signal and take care of
  different file starting offsets.

  In order to prevent this attack, the default was changed to cbc-essiv. 
  ESSIV uses a keyed hash of the sector number, with the encryption key as
  key.  This makes the IV unpredictable without knowing the encryption key
  and the watermarking attack fails.


  * **5.15 Are there any problems with "plain" IV? What is "plain64"?**

  First, "plain" and "plain64" are both not secure to use with CBC, see
  previous FAQ item.

  However there are modes, like XTS, that are secure with "plain" IV.  The
  next limit is that "plain" is 64 bit, with the upper 32 bit set to zero. 
  This means that on volumes larger than 2TiB, the IV repeats, creating a
  vulnerability that potentially leaks some data.  To avoid this, use
  "plain64", which uses the full sector number up to 64 bit.  Note that
  "plain64" requires a kernel 2.6.33 or more recent.  Also note that
  "plain64" is backwards compatible for volume sizes of maximum size 2TiB,
  but not for those > 2TiB.  Finally, "plain64" does not cause any
  performance penalty compared to "plain".


  * **5.16 What about XTS mode?**

  XTS mode is potentially even more secure than cbc-essiv (but only if
  cbc-essiv is insecure in your scenario).  It is a NIST standard and
  used, e.g.  in Truecrypt.  From version 1.6.0 of cryptsetup onwards,
  aes-xts-plain64 is the default for LUKS.  If you want to use it with a
  cryptsetup before version 1.6.0 or with plain dm-crypt, you have to
  specify it manually as "aes-xts-plain", i.e.
```
    cryptsetup -c aes-xts-plain luksFormat <device>
```
  For volumes >2TiB and kernels >= 2.6.33 use "plain64" (see FAQ item
  on "plain" and "plain64"):
```
    cryptsetup -c aes-xts-plain64 luksFormat <device>
```
  There is a potential security issue with XTS mode and large blocks. 
  LUKS and dm-crypt always use 512B blocks and the issue does not apply.


  * **5.17 Is LUKS FIPS-140-2 certified?**

  No.  But that is more a problem of FIPS-140-2 than of LUKS.  From a
  technical point-of-view, LUKS with the right parameters would be
  FIPS-140-2 compliant, but in order to make it certified, somebody has to
  pay real money for that.  And then, whenever cryptsetup is changed or
  extended, the certification lapses and has to be obtained again.

  From the aspect of actual security, LUKS with default parameters should
  be as good as most things that are FIPS-140-2 certified, although you
  may want to make sure to use /dev/random (by specifying --use-random on
  luksFormat) as randomness source for the volume key to avoid being
  potentially insecure in an entropy-starved situation.


  * **5.18 What about Plausible Deniability?**

  First let me attempt a definition for the case of encrypted filesystems:
  Plausible deniability is when you store data inside an encrypted
  container and it is not possible to prove it is there without having a
  special passphrase.  And at the same time it must be "plausible" that
  there actually is no hidden data there.

  As a simple entropy-analysis will show that here may be data there, the
  second part is what makes it tricky.

  There seem to  be a lot of misunderstandings about this idea, so let me
  make it clear that this refers to the situation where the attackers can
  prove that there is data that either may be random or may be part of a
  plausible-deniability scheme, they just cannot prove which one it is. 
  Hence a plausible-deniability scheme must hold up when the attackers
  know there is something potentially fishy.  If you just hide data and
  rely on it not being found, that is just simple deniability, not
  "plausible" deniability and I am not talking about that in the
  following.  Simple deniability against a low-competence attacker may be
  as simple as renaming a file or putting data into an unused part of a
  disk.  Simple deniability against a high-skill attacker with time to
  invest is usually pointless unless you go for advanced steganographic
  techniques, which have their own drawbacks, such as low data capacity.

  Now, the idea of plausible deniability is compelling and on a first
  glance it seems possible to do it.  And from a cryptographic point of
  view, it actually is possible.

  So, does the idea work in practice?  No, unfortunately.  The reasoning
  used by its proponents is fundamentally flawed in several ways and the
  cryptographic properties fail fatally when colliding with the real
  world.

  First, why should "I do not have a hidden partition" be any more
  plausible than "I forgot my crypto key" or "I wiped that partition with
  random data, nothing in there"?  I do not see any reason.

  Second, there are two types of situations: Either they cannot force you
  to give them the key (then you simply do not) or they can.  In the
  second case, they can always do bad things to you, because they cannot
  prove that you have the key in the first place!  This means they do not
  have to prove you have the key, or that this random looking data on your
  disk is actually encrypted data.  So the situation will allow them to
  waterboard/lock-up/deport you anyways, regardless of how "plausible"
  your deniability is.  Do not have a hidden partition you could show to
  them, but there are indications you may?  Too bad for you. 
  Unfortunately "plausible deniability" also means you cannot prove there
  is no hidden data.

  Third, hidden partitions are not that hidden.  There are basically just
  two possibilities: a) Make a large crypto container, but put a smaller
  filesystem in there and put the hidden partition into the free space. 
  Unfortunately this is glaringly obvious and can be detected in an
  automated fashion.  This means that the initial suspicion to put you
  under duress in order to make you reveal your hidden data is given.  b)
  Make a filesystem that spans the whole encrypted partition, and put the
  hidden partition into space not currently used by that filesystem. 
  Unfortunately that is also glaringly obvious, as you then cannot write
  to the filesystem without a high risk of destroying data in the hidden
  container.  Have not written anything to the encrypted filesystem in a
  while?  Too bad, they have the suspicion they need to do unpleasant
  things to you.

  To be fair, if you prepare option b) carefully and directly before going
  into danger, it may work.  But then, the mere presence of encrypted data
  may already be enough to get you into trouble in those places were they
  can demand encryption keys.

  Here is an additional reference for some problems with plausible
  deniability:
  https://www.schneier.com/academic/paperfiles/paper-truecrypt-dfs.pdf
  I strongly suggest you read it.

  So, no, I will not provide any instructions on how to do it with plain
  dm-crypt or LUKS.  If you insist on shooting yourself in the foot, you
  can figure out how to do it yourself.


 * **5.19 What about SSDs, Flash, Hybrid and SMR Drives?**

  The problem is that you cannot reliably erase parts of these devices,
  mainly due to wear-leveling and possibly defect management and delayed
  writes to the main data area.

  For example for SSDs, when overwriting a sector, what the device does is
  to move an internal sector (may be 128kB or even larger) to some pool of
  discarded, not-yet erased unused sectors, take a fresh empty sector from
  the empty-sector pool and copy the old sector over with the changes to
  the small part you wrote.  This is done in some fashion so that larger
  writes do not cause a lot of small internal updates.

  The thing is that the mappings between outside-addressable sectors and
  inside sectors is arbitrary (and the vendors are not talking).  Also the
  discarded sectors are not necessarily erased immediately.  They may
  linger a long time.

  For plain dm-crypt, the consequences are that older encrypted data may
  be lying around in some internal pools of the device.  Thus may or may
  not be a problem and depends on the application.  Remember the same can
  happen with a filesystem if consecutive writes to the same area of a
  file can go to different sectors.

  However, for LUKS, the worst case is that key-slots and LUKS header may
  end up in these internal pools.  This means that password management
  functionality is compromised (the old passwords may still be around,
  potentially for a very long time) and that fast erase by overwriting the
  header and key-slot area is insecure.

  Also keep in mind that the discarded/used pool may be large.  For
  example, a 240GB SSD has about 16GB of spare area in the chips that it
  is free to do with as it likes.  You would need to make each individual
  key-slot larger than that to allow reliable overwriting.  And that
  assumes the disk thinks all other space is in use.  Reading the internal
  pools using forensic tools is not that hard, but may involve some
  soldering.

  What to do?

  If you trust the device vendor (you probably should not...) you can try
  an ATA "secure erase" command.  That is not present in USB keys though
  and may or may not be secure for a hybrid drive.

  If you can do without password management and are fine with doing
  physical destruction for permanently deleting data (always after one or
  several full overwrites!), you can use plain dm-crypt.

  If you want or need all the original LUKS security features to work, you
  can use a detached LUKS header and put that on a conventional, magnetic
  disk.  That leaves potentially old encrypted data in the pools on the
  main disk, but otherwise you get LUKS with the same security as on a
  traditional magnetic disk.  Note however that storage vendors are prone
  to lying to their customers.  For example, it recently came out that
  HDDs sold without any warning or mentioning in the data-sheets were
  actually using SMR and that will write data first to a faster area and
  only overwrite the original data area some time later when things are
  quiet.

  If you are concerned about your laptop being stolen, you are likely fine
  using LUKS on an SSD or hybrid drive.  An attacker would need to have
  access to an old passphrase (and the key-slot for this old passphrase
  would actually need to still be somewhere in the SSD) for your data to
  be at risk.  So unless you pasted your old passphrase all over the
  Internet or the attacker has knowledge of it from some other source and
  does a targeted laptop theft to get at your data, you should be fine.


 * **5.20 LUKS1 is broken! It uses SHA-1!**

  No, it is not.  SHA-1 is (academically) broken for finding collisions,
  but not for using it in a key-derivation function.  And that collision
  vulnerability is for non-iterated use only.  And you need the hash-value
  in verbatim.

  This basically means that if you already have a slot-key, and you have
  set the PBKDF2 iteration count to 1 (it is > 10'000 normally), you could
  (maybe) derive a different passphrase that gives you the same slot-key.
  But if you have the slot-key, you can already unlock the key-slot and
  get the volume key, breaking everything.  So basically, this SHA-1
  vulnerability allows you to open a LUKS1 container with high effort when
  you already have it open.

  The real problem here is people that do not understand crypto and claim
  things are broken just because some mechanism is used that has been
  broken for a specific different use.  The way the mechanism is used
  matters very much.  A hash that is broken for one use can be completely
  secure for other uses and here it is.

  Since version 1.7.0, cryptsetup uses SHA-256 as default to ensure that
  it will be compatible in the future. There are already some systems 
  where SHA-1 is completely phased out or disabled by a security policy.


 * **5.21 Why is there no "Nuke-Option"?**

  A "Nuke-Option" or "Kill-switch" is a password that when entered upon
  unlocking instead wipes the header and all passwords.  So when somebody
  forces you to enter your password, you can destroy the data instead.

  While this sounds attractive at first glance, it does not make sense
  once a real security analysis is done.  One problem is that you have to
  have some kind of HSM (Hardware Security Module) in order to implement
  it securely.  In the movies, a HSM starts to smoke and melt once the
  Nuke-Option has been activated.  In actual reality, it just wipes some
  battery-backed RAM cells.  A proper HSM costs something like
  20'000...100'000 EUR/USD and there a Nuke-Option may make some sense. 
  BTW, a chipcard or a TPM is not a HSM, although some vendors are
  promoting that myth.

  Now, a proper HSMs will have a wipe option but not a Nuke-Option, i.e. 
  you can explicitly wipe the HSM, but by a different process than
  unlocking it takes.  Why is that?  Simple: If somebody can force you to
  reveal passwords, then they can also do bad things to you if you do not
  or if you enter a nuke password instead.  Think locking you up for a few
  years for "destroying evidence" or for far longer and without trial for
  being a "terrorist suspect".  No HSM maker will want to expose its
  customers to that risk.

  Now think of the typical LUKS application scenario, i.e.  disk
  encryption.  Usually the ones forcing you to hand over your password
  will have access to the disk as well, and, if they have any real
  suspicion, they will mirror your disk before entering anything supplied
  by you.  This neatly negates any Nuke-Option.  If they have no suspicion
  (just harassing people that cross some border for example), the
  Nuke-Option would work, but see above about likely negative consequences
  and remember that a Nuke-Option may not work reliably on SSD and hybrid
  drives anyways.

  Hence my advice is to never take data that you do not want to reveal
  into any such situation in the first place.  There is no need to
  transfer data on physical carriers today.  The Internet makes it quite
  possible to transfer data between arbitrary places and modern encryption
  makes it secure.  If you do it right, nobody will even be able to
  identify source or destination.  (How to do that is out of scope of this
  document.  It does require advanced skills in this age of pervasive
  surveillance.)

  Hence, LUKS has no kill option because it would do much more harm than
  good.


 * **5.22 Does cryptsetup open network connections to websites, etc. ?**

  This question seems not to make much sense at first glance, but here is
  an example form the real world: The TrueCrypt GUI has a "Donation"
  button.  Press it, and a web-connection to the TrueCrypt website is
  opened via the default browser, telling everybody that listens that you
  use TrueCrypt.  In the worst case, things like this can get people
  tortured or killed.

  So: Cryptsetup will never open any network connections except the
  local netlink socket it needs to talk to the kernel crypto API.

  In addition, the installation package should contain all documentation,
  including this FAQ, so that you do not have to go to a web-site to read
  it.  (If your distro cuts the docu, please complain to them.) In
  security software, any connection initiated to anywhere outside your
  machine should always be the result of an explicit request for such a
  connection by the user and cryptsetup will stay true to that principle.


 * **5.23 What is cryptsetup CVE-2021-4122?**

  CVE-2021-4122 describes a possible attack against data confidentiality
  through LUKS2 online reencryption extension crash recovery.

  An attacker can modify on-disk metadata to simulate decryption in
  progress with crashed (unfinished) reencryption step and persistently
  decrypt part of the LUKS device.

  This attack requires repeated physical access to the LUKS device but
  no knowledge of user passphrases.

  The decryption step is performed after a valid user activates
  the device with a correct passphrase and modified metadata.
  There are no visible warnings for the user that such recovery happened
  (except using the luksDump command). The attack can also be reversed
  afterward (simulating crashed encryption from a plaintext) with
  possible modification of revealed plaintext.

  The problem was fixed in cryptsetup version 2.4.3 and 2.3.7.

  For more info, please see the report here:
  https://seclists.org/oss-sec/2022/q1/34


# 6. Backup and Data Recovery


 * **6.1 Why do I need Backup?**

  First, disks die.  The rate for well-treated (!) disk is about 5% per
  year, which is high enough to worry about.  There is some indication
  that this may be even worse for some SSDs.  This applies both to LUKS
  and plain dm-crypt partitions.

  Second, for LUKS, if anything damages the LUKS header or the key-stripe
  area then decrypting the LUKS device can become impossible.  This is a
  frequent occurrence.  For example an accidental format as FAT or some
  software overwriting the first sector where it suspects a partition boot
  sector typically makes a LUKS1 partition permanently inaccessible.  See
  more below on LUKS header damage.

  So, data-backup in some form is non-optional.  For LUKS, you may also
  want to store a header backup in some secure location.  This only needs
  an update if you change passphrases.


 * **6.2 How do I backup a LUKS header?**

  While you could just copy the appropriate number of bytes from the start
  of the LUKS partition, the best way is to use command option
  "luksHeaderBackup" of cryptsetup.  This protects also against errors
  when non-standard parameters have been used in LUKS partition creation.  
  Example:
```
    cryptsetup luksHeaderBackup --header-backup-file <file> <device>
```
  To restore, use the inverse command, i.e.
```
    cryptsetup luksHeaderRestore --header-backup-file <file> <device>
```
  If you are unsure about a header to be restored, make a backup of the
  current one first!  You can also test the header-file without restoring
  it by using the --header option for a detached header like this:
```
    cryptsetup --header <file> luksOpen <device> </dev/mapper/name>
```
  If that unlocks your key-slot, you are good. Do not forget to close
  the device again.

  Under some circumstances (damaged header), this fails.  Then use the
  following steps in case it is LUKS1:

  First determine the volume (volume) key size:
```
    cryptsetup luksDump <device>
```
  gives a line of the form
```
    MK bits:        <bits>
```
  with bits equal to 256 for the old defaults and 512 for the new
  defaults.  256 bits equals a total header size of 1'052'672 Bytes and
  512 bits one of 2MiB.  (See also Item 6.12) If luksDump fails, assume
  2MiB, but be aware that if you restore that, you may also restore the
  first 1M or so of the filesystem.  Do not change the filesystem if you
  were unable to determine the header size!  With that, restoring a
  too-large header backup is still safe.

  Second, dump the header to file. There are many ways to do it, I
  prefer the following:
```
    head -c 1052672 <device>  >  header_backup.dmp
```
  or
```
    head -c 2M <device>  >  header_backup.dmp
```
  for a 2MiB header. Verify the size of the dump-file to be sure.

  To restore such a backup, you can try luksHeaderRestore or do a more
  basic
```
    cat header_backup.dmp  >  <device>
```


  * **6.3 How do I test for a LUKS header?**

  Use
```
    cryptsetup -v isLuks <device>
```
  on the device.  Without the "-v" it just signals its result via
  exit-status.  You can also use the more general test
```
    blkid -p <device>
```
  which will also detect other types and give some more info.  Omit
  "-p" for old versions of blkid that do not support it.


  * **6.4 How do I backup a LUKS or dm-crypt partition?**

  There are two options, a sector-image and a plain file or filesystem
  backup of the contents of the partition.  The sector image is already
  encrypted, but cannot be compressed and contains all empty space.  The
  filesystem backup can be compressed, can contain only part of the
  encrypted device, but needs to be encrypted separately if so desired.

  A sector-image will contain the whole partition in encrypted form, for
  LUKS the LUKS header, the keys-slots and the data area.  It can be done
  under Linux e.g.  with dd_rescue (for a direct image copy) and with
  "cat" or "dd".  Examples:
```
    cat /dev/sda10 > sda10.img
    dd_rescue /dev/sda10 sda10.img
```
  You can also use any other backup software that is capable of making a
  sector image of a partition.  Note that compression is ineffective for
  encrypted data, hence it does not make sense to use it.

  For a filesystem backup, you decrypt and mount the encrypted partition
  and back it up as you would a normal filesystem.  In this case the
  backup is not encrypted, unless your encryption method does that.  For
  example you can encrypt a backup with "tar" as follows with GnuPG:
```
    tar cjf - <path> | gpg --cipher-algo AES -c - > backup.tbz2.gpg
```
  And verify the backup like this if you are at "path":
```
    cat backup.tbz2.gpg | gpg - | tar djf -
```
  Note: Always verify backups, especially encrypted ones!

  There is one problem with verifying like this: The kernel may still have
  some files cached and in fact verify them against RAM or may even verify
  RAM against RAM, which defeats the purpose of the exercise.  The
  following command empties the kernel caches:
```
    echo 3 > /proc/sys/vm/drop_caches
```
  Run it after backup and before verify.

  In both cases GnuPG will ask you interactively for your symmetric key. 
  The verify will only output errors.  Use "tar dvjf -" to get all
  comparison results.  To make sure no data is written to disk
  unencrypted, turn off swap if it is not encrypted before doing the
  backup.

  Restore works like certification with the 'd' ('difference') replaced 
  by 'x' ('eXtract').  Refer to the man-page of tar for more explanations 
  and instructions.  Note that with default options tar will overwrite 
  already existing files without warning.  If you are unsure about how 
  to use tar, experiment with it in a location where you cannot do damage.

  You can of course use different or no compression and you can use an
  asymmetric key if you have one and have a backup of the secret key that
  belongs to it.

  A second option for a filesystem-level backup that can be used when the
  backup is also on local disk (e.g.  an external USB drive) is to use a
  LUKS container there and copy the files to be backed up between both
  mounted containers.  Also see next item.


  * **6.5 Do I need a backup of the full partition? Would the header and key-slots not be enough?**

  Backup protects you against two things: Disk loss or corruption and user
  error.  By far the most questions on the dm-crypt mailing list about how
  to recover a damaged LUKS partition are related to user error.  For
  example, if you create a new filesystem on a non-mapped LUKS container,
  chances are good that all data is lost permanently.

  For this case, a header+key-slot backup would often be enough.  But keep
  in mind that a well-treated (!) HDD has roughly a failure risk of 5% per
  year.  It is highly advisable to have a complete backup to protect
  against this case.


  * **6.6 What do I need to backup if I use "decrypt_derived"?**

  This is a script in Debian, intended for mounting /tmp or swap with a
  key derived from the volume key of an already decrypted device.  If you
  use this for an device with data that should be persistent, you need to
  make sure you either do not lose access to that volume key or have a
  backup of the data.  If you derive from a LUKS device, a header backup
  of that device would cover backing up the volume key.  Keep in mind that
  this does not protect against disk loss.

  Note: If you recreate the LUKS header of the device you derive from
  (using luksFormat), the volume key changes even if you use the same
  passphrase(s) and you will not be able to decrypt the derived device
  with the new LUKS header.


  * **6.7 Does a backup compromise security?**

  Depends on how you do it.  However if you do not have one, you are going
  to eventually lose your encrypted data.

  There are risks introduced by backups.  For example if you
  change/disable a key-slot in LUKS, a binary backup of the partition will
  still have the old key-slot.  To deal with this, you have to be able to
  change the key-slot on the backup as well, securely erase the backup or
  do a filesystem-level backup instead of a binary one.

  If you use dm-crypt, backup is simpler: As there is no key management,
  the main risk is that you cannot wipe the backup when wiping the
  original.  However wiping the original for dm-crypt should consist of
  forgetting the passphrase and that you can do without actual access to
  the backup.

  In both cases, there is an additional (usually small) risk with binary
  backups: An attacker can see how many sectors and which ones have been
  changed since the backup.  To prevent this, use a filesystem level
  backup method that encrypts the whole backup in one go, e.g.  as
  described above with tar and GnuPG.

  My personal advice is to use one USB disk (low value data) or three
  disks (high value data) in rotating order for backups, and either use
  independent LUKS partitions on them, or use encrypted backup with tar
  and GnuPG.

  If you do network-backup or tape-backup, I strongly recommend to go
  the filesystem backup path with independent encryption, as you
  typically cannot reliably delete data in these scenarios, especially
  in a cloud setting.  (Well, you can burn the tape if it is under your
  control...)


  * **6.8 What happens if I overwrite the start of a LUKS partition or damage the LUKS header or key-slots?**

  There are two critical components for decryption: The salt values in the
  key-slot descriptors of the header and the key-slots.  For LUKS2 they
  are a bit better protected.  but for LUKS1, these are right in the first
  sector.  If the salt values are overwritten or changed, nothing (in the
  cryptographically strong sense) can be done to access the data, unless
  there is a backup of the LUKS header.  If a key-slot is damaged, the
  data can still be read with a different key-slot, if there is a
  remaining undamaged and used key-slot.  Note that in order to make a
  key-slot completely unrecoverable, changing about 4-6 bits in random
  locations of its 128kiB size is quite enough.


  * **6.9 What happens if I (quick) format a LUKS partition?**

  I have not tried the different ways to do this, but very likely you will
  have written a new boot-sector, which in turn overwrites the LUKS
  header, including the salts, making your data permanently irretrievable,
  unless you have a LUKS header backup.  For LUKS2 this may still be
  recoverable without that header backup, for LUKS1 it is not.  You may
  also damage the key-slots in part or in full.  See also last item.


  * **6.10 How do I recover the volume key from a mapped LUKS1 container?**

  Note: LUKS2 uses the kernel keyring to store keys and hence this
  procedure does not work unless you have explicitly disabled the use of
  the keyring with "--disable-keyring" on opening.
 
  This is typically only needed if you managed to damage your LUKS1
  header, but the container is still mapped, i.e.  "luksOpen"ed.  It also
  helps if you have a mapped container that you forgot or do not know a
  passphrase for (e.g.  on a long running server.)

  WARNING: Things go wrong, do a full backup before trying this!

  WARNING: This exposes the volume key of the LUKS1 container.  Note that
  both ways to recreate a LUKS header with the old volume key described
  below will write the volume key to disk.  Unless you are sure you have
  securely erased it afterwards, e.g.  by writing it to an encrypted
  partition, RAM disk or by erasing the filesystem you wrote it to by a
  complete overwrite, you should change the volume key afterwards. 
  Changing the volume key requires a full data backup, luksFormat and then
  restore of the backup.  Alternatively the tool cryptsetup-reencrypt from
  the cryptsetup package can be used to change the volume key (see its
  man-page), but a full backup is still highly recommended.

  First, there is a script by Milan that automates the whole process,
  except generating a new LUKS1 header with the old volume key (it prints
  the command for that though):

  https://gitlab.com/cryptsetup/cryptsetup/blob/main/misc/luks-header-from-active

  You can also do this manually. Here is how:

  - Get the volume key from the device mapper.  This is done by the
  following command.  Substitute c5 for whatever you mapped to:
```
    # dmsetup table --target crypt --showkey /dev/mapper/c5

    Result:
    0 200704 crypt aes-cbc-essiv:sha256
    a1704d9715f73a1bb4db581dcacadaf405e700d591e93e2eaade13ba653d0d09
    0 7:0 4096
```
  The result is actually one line, wrapped here for clarity.  The long
  hex string is the volume key.

  - Convert the volume key to a binary file representation.  You can do
  this manually, e.g.  with hexedit.  You can also use the tool "xxd"
  from vim like this:
```
    echo "a1704d9....53d0d09" | xxd -r -p > <volume-key-file>
```

  - Do a luksFormat to create a new LUKS1 header.

    NOTE: If your header is intact and you just forgot the passphrase,
    you can just set a new passphrase, see next sub-item.

  Unmap the device before you do that (luksClose). Then do
```
    cryptsetup luksFormat --volume-key-file=<volume-key-file> <luks device>
```
  Note that if the container was created with other than the default
  settings of the cryptsetup version you are using, you need to give
  additional parameters specifying the deviations.  If in doubt, try the
  script by Milan.  It does recover the other parameters as well.

  Side note: This is the way the decrypt_derived script gets at the volume
  key.  It just omits the conversion and hashes the volume key string.

  - If the header is intact and you just forgot the passphrase, just
  set a new passphrase like this:
```
      cryptsetup luksAddKey --volume-key-file=<volume-key-file> <luks device>
```
  You may want to disable the old one afterwards.


  * **6.11 What does the on-disk structure of dm-crypt look like?**

  There is none.  dm-crypt takes a block device and gives encrypted access
  to each of its blocks with a key derived from the passphrase given.  If
  you use a cipher different than the default, you have to specify that as
  a parameter to cryptsetup too.  If you want to change the password, you
  basically have to create a second encrypted device with the new
  passphrase and copy your data over.  On the plus side, if you
  accidentally overwrite any part of a dm-crypt device, the damage will be
  limited to the area you overwrote.


  * **6.12 What does the on-disk structure of LUKS1 look like?**

  Note: For LUKS2, refer to the LUKS2 document referenced in Item 1.2

  A LUKS1 partition consists of a header, followed by 8 key-slot
  descriptors, followed by 8 key slots, followed by the encrypted data
  area.

  Header and key-slot descriptors fill the first 592 bytes.  The key-slot
  size depends on the creation parameters, namely on the number of
  anti-forensic stripes, key material offset and volume key size.

  With the default parameters, each key-slot is a bit less than 128kiB in
  size.  Due to sector alignment of the key-slot start, that means the key
  block 0 is at offset 0x1000-0x20400, key block 1 at offset
  0x21000-0x40400, and key block 7 at offset 0xc1000-0xe0400.  The space
  to the next full sector address is padded with zeros.  Never used
  key-slots are filled with what the disk originally contained there, a
  key-slot removed with "luksRemoveKey" or "luksKillSlot" gets filled with
  0xff.  Due to 2MiB default alignment, start of the data area for
  cryptsetup 1.3 and later is at 2MiB, i.e.  at 0x200000.  For older
  versions, it is at 0x101000, i.e.  at 1'052'672 bytes, i.e.  at 1MiB +
  4096 bytes from the start of the partition.  Incidentally,
  "luksHeaderBackup" for a LUKS container created with default parameters
  dumps exactly the first 2MiB (or 1'052'672 bytes for headers created
  with cryptsetup versions < 1.3) to file and "luksHeaderRestore" restores
  them.

  For non-default parameters, you have to figure out placement yourself. 
  "luksDump" helps.  See also next item.  For the most common non-default
  settings, namely aes-xts-plain with 512 bit key, the offsets are: 1st
  keyslot 0x1000-0x3f800, 2nd keyslot 0x40000-0x7e000, 3rd keyslot
  0x7e000-0xbd800, ..., and start of bulk data at 0x200000.

  The exact specification of the format is here:
     https://gitlab.com/cryptsetup/cryptsetup/wikis/Specification

  For your convenience, here is the LUKS1 header with hex offsets.  
  NOTE:
  The spec counts key-slots from 1 to 8, but the cryptsetup tool counts
  from 0 to 7.  The numbers here refer to the cryptsetup numbers.

```
Refers to LUKS1 On-Disk Format Specification Version 1.2.3

LUKS1 header:

offset  length  name             data type  description
-----------------------------------------------------------------------
0x0000   0x06   magic            byte[]     'L','U','K','S', 0xba, 0xbe
     0      6
0x0006   0x02   version          uint16_t   LUKS version
     6      3
0x0008   0x20   cipher-name      char[]     cipher name spec.
     8     32
0x0028   0x20   cipher-mode      char[]     cipher mode spec.
    40     32
0x0048   0x20   hash-spec        char[]     hash spec.
    72     32
0x0068   0x04   payload-offset   uint32_t   bulk data offset in sectors
   104      4                               (512 bytes per sector)
0x006c   0x04   key-bytes        uint32_t   number of bytes in key
   108      4
0x0070   0x14   mk-digest        byte[]     volume key checksum
   112     20                               calculated with PBKDF2
0x0084   0x20   mk-digest-salt   byte[]     salt for PBKDF2 when
   132     32                               calculating mk-digest
0x00a4   0x04   mk-digest-iter   uint32_t   iteration count for PBKDF2
   164      4                               when calculating mk-digest
0x00a8   0x28   uuid             char[]     partition UUID
   168     40
0x00d0   0x30   key-slot-0       key slot   key slot 0
   208     48
0x0100   0x30   key-slot-1       key slot   key slot 1
   256     48
0x0130   0x30   key-slot-2       key slot   key slot 2
   304     48
0x0160   0x30   key-slot-3       key slot   key slot 3
   352     48
0x0190   0x30   key-slot-4       key slot   key slot 4
   400     48
0x01c0   0x30   key-slot-5       key slot   key slot 5
   448     48
0x01f0   0x30   key-slot-6       key slot   key slot 6
   496     48
0x0220   0x30   key-slot-7       key slot   key slot 7
   544     48


Key slot:

offset  length  name                  data type  description
-------------------------------------------------------------------------
0x0000   0x04   active                uint32_t   key slot enabled/disabled
     0      4
0x0004   0x04   iterations            uint32_t   PBKDF2 iteration count
     4      4
0x0008   0x20   salt                  byte[]     PBKDF2 salt
     8     32
0x0028   0x04   key-material-offset   uint32_t   key start sector
    40      4                                    (512 bytes/sector)
0x002c   0x04   stripes               uint32_t   number of anti-forensic
    44      4                                    stripes
```


  * **6.13 What is the smallest possible LUKS1 container?**

  Note: From cryptsetup 1.3 onwards, alignment is set to 1MB.  With modern
  Linux partitioning tools that also align to 1MB, this will result in
  alignment to 2k sectors and typical Flash/SSD sectors, which is highly
  desirable for a number of reasons.  Changing the alignment is not
  recommended.

  That said, with default parameters, the data area starts at exactly 2MB
  offset (at 0x101000 for cryptsetup versions before 1.3).  The smallest
  data area you can have is one sector of 512 bytes.  Data areas of 0
  bytes can be created, but fail on mapping.

  While you cannot put a filesystem into something this small, it may
  still be used to contain, for example, key.  Note that with current
  formatting tools, a partition for a container this size will be 3MiB
  anyways.  If you put the LUKS container into a file (via losetup and a
  loopback device), the file needs to be 2097664 bytes in size, i.e.  2MiB
  + 512B.

  The two ways to influence the start of the data area are key-size and
  alignment.

  For alignment, you can go down to 1 on the parameter.  This will still
  leave you with a data-area starting at 0x101000, i.e.  1MiB+4096B
  (default parameters) as alignment will be rounded up to the next
  multiple of 8 (i.e.  4096 bytes) If in doubt, do a dry-run on a larger
  file and dump the LUKS header to get actual information.

  For key-size, you can use 128 bit (e.g.  AES-128 with CBC), 256 bit
  (e.g.  AES-256 with CBC) or 512 bit (e.g.  AES-256 with XTS mode).  You
  can do 64 bit (e.g.  blowfish-64 with CBC), but anything below 128 bit
  has to be considered insecure today.

  Example 1 - AES 128 bit with CBC:
```
      cryptsetup luksFormat -s 128 --align-payload=8 <device>
```
  This results in a data offset of 0x81000, i.e. 516KiB or 528384
  bytes.  Add one 512 byte sector and the smallest LUKS container size
  with these parameters is 516KiB + 512B or 528896 bytes.

  Example 2 - Blowfish 64 bit with CBC (WARNING: insecure):
```
      cryptsetup luksFormat -c blowfish -s 64 --align-payload=8 /dev/loop0
```
  This results in a data offset of 0x41000, i.e. 260kiB or 266240
  bytes, with a minimal LUKS1 container size of 260kiB + 512B or 266752
  bytes.


  * **6.14 I think this is overly complicated. Is there an alternative?**

  Not really.  Encryption comes at a price.  You can use plain dm-crypt to
  simplify things a bit.  It does not allow multiple passphrases, but on
  the plus side, it has zero on disk description and if you overwrite some
  part of a plain dm-crypt partition, exactly the overwritten parts are
  lost (rounded up to full sectors).

  * **6.15 Can I clone a LUKS container?**

  You can, but it breaks security, because the cloned container has the
  same header and hence the same volume key.  Even if you change the 
  passphrase(s), the volume key stays the same.  That means whoever has 
  access to one of the clones can decrypt them all, completely bypassing 
  the passphrases. 

  While you can use cryptsetup-reencrypt to change the volume key, 
  this is probably more effort than to create separate LUKS containers
  in the first place.

  The right way to do this is to first luksFormat the target container,
  then to clone the contents of the source container, with both containers
  mapped, i.e.  decrypted.  You can clone the decrypted contents of a LUKS
  container in binary mode, although you may run into secondary issues
  with GUIDs in filesystems, partition tables, RAID-components and the
  like.  These are just the normal problems binary cloning causes.

  Note that if you need to ship (e.g.) cloned LUKS containers with a
  default passphrase, that is fine as long as each container was
  individually created (and hence has its own volume key).  In this case,
  changing the default passphrase will make it secure again.

  * **6.16 How to convert the printed volume key to a raw one?**
  A volume key printed via something like:
```
      cryptsetup --dump-volume-key luksDump /dev/<device> >volume-key
```
(i.e. without using `--volume-key-file`), which gives something like:
```
LUKS header information for /dev/<device>
Cipher name:   	aes
Cipher mode:   	xts-plain64
Payload offset:	32768
UUID:          	6e914442-e8b5-4eb5-98c4-5bf0cf17ecad
MK bits:       	512
MK dump:	e0 3f 15 c2 0f e5 80 ab 35 b4 10 03 ae 30 b9 5d 
		4c 0d 28 9e 1b 0f e3 b0 50 57 ef d4 4d 53 a0 12 
		b7 4e 43 a1 20 7e c5 02 1f f1 f5 08 04 3c f5 20 
		a6 0b 23 f6 7b 53 55 aa 22 d8 aa 02 e0 2f d5 04 
```
can be converted to the raw volume key for example via:
```
      sed -E -n '/^MK dump:\t/,/^[^\t]/{0,/^MK dump:\t/s/^MK dump://; /^([^\t].*)?$/q; s/\t+//p;};' volume-key  |  xxd -r -p
```




# 7. Interoperability with other Disk Encryption Tools


  * **7.1 What is this section about?**

  Cryptsetup for plain dm-crypt can be used to access a number of on-disk
  formats created by tools like loop-aes patched into losetup.  This
  sometimes works and sometimes does not.  This section collects insights
  into what works, what does not and where more information is required.

  Additional information may be found in the mailing-list archives,
  mentioned at the start of this FAQ document.  If you have a solution
  working that is not yet documented here and think a wider audience may
  be interested, please email the FAQ maintainer.


  * **7.2 loop-aes: General observations.**

  One problem is that there are different versions of losetup around. 
  loop-aes is a patch for losetup.  Possible problems and deviations
  from cryptsetup option syntax include:

  - Offsets specified in bytes (cryptsetup: 512 byte sectors)

  - The need to specify an IV offset

  - Encryption mode needs specifying (e.g. "-c twofish-cbc-plain")

  - Key size needs specifying (e.g. "-s 128" for 128 bit keys)

  - Passphrase hash algorithm needs specifying

  Also note that because plain dm-crypt and loop-aes format does not have
  metadata, and while the loopAES extension for cryptsetup tries
  autodetection (see command loopaesOpen), it may not always work.  If you
  still have the old set-up, using a verbosity option (-v) on mapping with
  the old tool or having a look into the system logs after setup could
  give you the information you need.  Below, there are also some things
  that worked for somebody.


  * **7.3 loop-aes patched into losetup on Debian 5.x, kernel 2.6.32**

  In this case, the main problem seems to be that this variant of
  losetup takes the offset (-o option) in bytes, while cryptsetup takes
  it in sectors of 512 bytes each.  

  Example: The losetup command
```
    losetup -e twofish -o 2560 /dev/loop0 /dev/sdb1
    mount /dev/loop0 mount-point
```
  translates to
```
    cryptsetup create -c twofish -o 5 --skip 5 e1 /dev/sdb1
    mount /dev/mapper/e1 mount-point
```


  * **7.4 loop-aes with 160 bit key**

  This seems to be sometimes used with twofish and blowfish and represents
  a 160 bit ripemed160 hash output padded to 196 bit key length.  It seems
  the corresponding options for cryptsetup are
```
    --cipher twofish-cbc-null -s 192 -h ripemd160:20
```


  * **7.5 loop-aes v1 format OpenSUSE**

  Apparently this is done by older OpenSUSE distros and stopped working
  from OpenSUSE 12.1 to 12.2.  One user had success with the following:
```
    cryptsetup create <target> <device> -c aes -s 128 -h sha256
```


  * **7.6 Kernel encrypted loop device (cryptoloop)**

  There are a number of different losetup implementations for using
  encrypted loop devices so getting this to work may need a bit of
  experimentation.

  NOTE: Do NOT use this for new containers! Some of the existing
  implementations are insecure and future support is uncertain.

  Example for a compatible mapping:
```
    losetup -e twofish -N /dev/loop0 /image.img
```
  translates to
```
    cryptsetup create image_plain /image.img -c twofish-cbc-plain -H plain
```
  with the mapping being done to /dev/mapper/image_plain instead of
  to /dev/loop0.

  More details:

  Cipher, mode and password hash (or no hash):
```
  -e cipher [-N]        => -c cipher-cbc-plain -H plain [-s 256]
  -e cipher             => -c cipher-cbc-plain -H ripemd160 [-s 256]
```

  Key size and offsets (losetup: bytes, cryptsetuop: sectors of 512 bytes):
```
  -k 128                 => -s 128
  -o 2560                => -o 5 -p 5       # 2560/512 = 5
```

  There is no replacement for --pass-fd, it has to be emulated using
  keyfiles, see the cryptsetup man-page.


# 8. Issues with Specific Versions of cryptsetup


  * **8.1 When using the create command for plain dm-crypt with cryptsetup 1.1.x, the mapping is incompatible and my data is not accessible anymore!**

  With cryptsetup 1.1.x, the distro maintainer can define different
  default encryption modes.  You can check the compiled-in defaults using
  "cryptsetup --help".  Moreover, the plain device default changed because
  the old IV mode was vulnerable to a watermarking attack.

  If you are using a plain device and you need a compatible mode, just
  specify cipher, key size and hash algorithm explicitly.  For
  compatibility with cryptsetup 1.0.x defaults, simple use the following:
```
    cryptsetup create -c aes-cbc-plain -s 256 -h ripemd160 <name> <dev>
```
  LUKS stores cipher and mode in the metadata on disk, avoiding this
  problem.


  * **8.2 cryptsetup on SLED 10 has problems...**

  SLED 10 is missing an essential kernel patch for dm-crypt, which is
  broken in its kernel as a result.  There may be a very old version of
  cryptsetup (1.0.x) provided by SLED, which should also not be used
  anymore as well.  My advice would be to drop SLED 10.


  * **8.3 Gcrypt 1.6.x and later break Whirlpool**

  It is the other way round: In gcrypt 1.5.x, Whirlpool is broken and it
  was fixed in 1.6.0 and later.  If you selected whirlpool as hash on
  creation of a LUKS container, it does not work anymore with the fixed
  library.  This shows one serious risk of using rarely used settings.

  Note that at the time this FAQ item was written, 1.5.4 was the latest
  1.5.x version and it has the flaw, i.e.  works with the old Whirlpool
  version.  Possibly later 1.5.x versions will work as well.

  The only two ways to access older LUKS containers created with Whirlpool
  are to either decrypt with an old gcrypt version that has the flaw or to
  use a compatibility feature introduced in cryptsetup 1.6.4 and gcrypt
  1.6.1 or later.  Version 1.6.0 cannot be used.

  Steps:

  - Make at least a header backup or better, refresh your full backup. 
  (You have a full backup, right?  See Item 6.1 and following.)

  - Make sure you have cryptsetup 1.6.4 or later and check the gcrypt
    version:
```
     cryptsetup luksDump <your luks device> --debug | grep backend
```
  If gcrypt is at version 1.5.x or before:

  - Reencrypt the LUKS header with a different hash. (Requires entering
  all keyslot passphrases.  If you do not have all, remove the ones you
  do not have before.):
```
     cryptsetup-reencrypt --keep-key --hash sha256 <your luks device>
```
  If gcrypt is at version 1.6.1 or later:

  - Patch the hash name in the LUKS header from "whirlpool" to
  "whirlpool_gcryptbug".  This activates the broken implementation. 
  The detailed header layout is in Item 6.12 of this FAQ and in the
  LUKS on-disk format specification.  One way to change the hash is
  with the following command:
```
     echo -n -e 'whirlpool_gcryptbug\0' | dd of=<luks device> bs=1 seek=72 conv=notrunc
```
  - You can now open the device again. It is highly advisable to change
  the hash now with cryptsetup-reencrypt as described above.  While you
  can reencrypt to use the fixed whirlpool, that may not be a good idea
  as almost nobody seems to use it and hence the long time until the
  bug was discovered.


# 9. The Initrd question


  * **9.1 My initrd is broken with cryptsetup**

  That is not nice!  However the initrd is supplied by your distribution,
  not by the cryptsetup project and hence you should complain to them.  We
  cannot really do anything about it.


  * **9.2 CVE-2016-4484 says cryptsetup is broken!**

  Not really. It says the initrd in some Debian versions have a behavior 
  that under some very special and unusual conditions may be considered
  a vulnerability. 

  What happens is that you can trick the initrd to go to a rescue-shell if
  you enter the LUKS password wrongly in a specific way.  But falling back
  to a rescue shell on initrd errors is a sensible default behavior in the
  first place.  It gives you about as much access as booting a rescue
  system from CD or USB-Stick or as removing the disk would give you.  So
  this only applies when an attacker has physical access, but cannot boot
  anything else or remove the disk.  These will be rare circumstances
  indeed, and if you rely on the default distribution initrd to keep you
  safe under these circumstances, then you have bigger problems than this
  somewhat expected behavior.

  The CVE was exaggerated and should not be assigned to upstream
  cryptsetup in the first place (it is a distro specific initrd issue). 
  It was driven more by a try to make a splash for self-aggrandizement,
  than by any actual security concerns.  Ignore it.


  * **9.3 How do I do my own initrd with cryptsetup?**

  Note: The instructions here apply to an initrd in initramfs format, not
  to an initrd in initrd format.  The latter is a filesystem image, not a
  cpio-archive, and seems to not be widely used anymore.
 
  It depends on the distribution.  Below, I give a very simple example and
  step-by-step instructions for Debian.  With a bit of work, it should be
  possible to adapt this to other distributions.  Note that the
  description is pretty general, so if you want to do other things with an
  initrd it provides a useful starting point for that too.

  01) Unpacking an existing initrd to use as template

  A Linux initrd is in gzip'ed cpio format. To unpack it, use something
  like this: 
``` 
     mkdir tmp; cd tmp; cat ../initrd | gunzip | cpio -id
```
  After this, you have the full initrd content in tmp/

  02) Inspecting the init-script

  The init-script is the only thing the kernel cares about.  All activity
  starts there.  Its traditional location is /sbin/init on disk, but /init
  in an initrd.  In an initrd unpacked as above it is tmp/init.

  While init can be a binary despite usually being called "init script",
  in Debian the main init on the root partition is a binary, but the init
  in the initrd (and only that one is called by the kernel) is a script
  and starts like this:
```
    #!/bin/sh
    ....
```
  The "sh" used here is in tmp/bin/sh as just unpacked, and in Debian it
  currently is a busybox.

  03) Creating your own initrd

  The two examples below should give you most of what is needed.  This is
  tested with LUKS1 and should work with LUKS2 as well.

  Here is a really minimal example.  It does nothing but set up some
  things and then drop to an interactive shell.  It is perfect to try out
  things that you want to go into the init-script.
```
   #!/bin/sh
   export PATH=/sbin:/bin  
   [ -d /sys ] || mkdir /sys
   [ -d /proc ] || mkdir /proc
   [ -d /tmp ] || mkdir /tmp
   mount -t sysfs -o nodev,noexec,nosuid sysfs /sys
   mount -t proc -o nodev,noexec,nosuid proc /proc
   echo "initrd is running, starting BusyBox..."
   exec /bin/sh --login
```

  Here is an example that opens the first LUKS-partition it finds with the
  hard-coded password "test2" and then mounts it as root-filesystem.  This
  is intended to be used on an USB-stick that after boot goes into a safe,
  as it contains the LUKS-passphrase in plain text and is not secure to be
  left in the system.  The script contains debug-output that should make it
  easier to see what is going on.  Note that the final hand-over to the init
  on the encrypted root-partition is done by "exec switch_root /mnt/root
  /sbin/init", after mounting the decrypted LUKS container with "mount
  /dev/mapper/c1 /mnt/root".  The second argument of switch_root is relative
  to the first argument, i.e.  the init started with this command is really
  /mnt/sbin/init before switch_root runs.
```
   #!/bin/sh
   export PATH=/sbin:/bin
   [ -d /sys ] || mkdir /sys
   [ -d /proc ] || mkdir /proc
   [ -d /tmp ] || mkdir /tmp
   mount -t sysfs -o nodev,noexec,nosuid sysfs /sys
   mount -t proc -o nodev,noexec,nosuid proc /proc
   echo "detecting LUKS containers in sda1-10, sdb1-10"; sleep 1
   for i in a b
   do
     for j in 1 2 3 4 5 6 7 8 9 10
     do
       sleep 0.5
       d="/dev/sd"$i""$j
       echo -n $d
       cryptsetup isLuks $d >/dev/null 2>&1
       r=$?
       echo -n "  result: "$r""
       # 0 = is LUKS, 1 = is not LUKS, 4 = other error
       if expr $r = 0 > /dev/null
       then
         echo "  is LUKS, attempting unlock"
         echo -n "test2" | cryptsetup luksOpen --key-file=- $d c1
         r=$?
         echo "  result of unlock attempt: "$r""
         sleep 2
         if expr $r = 0 > /dev/null
         then
           echo "*** LUKS partition unlocked, switching root *** 
           echo "    (waiting 30 seconds before doing that)"
           mount /dev/mapper/c1 /mnt/root
           sleep 30
           exec switch_root /mnt/root /sbin/init
         fi
       else
         echo "  is not LUKS"
       fi
     done
   done
   echo "FAIL finding root on LUKS, loading BusyBox..."; sleep 5
   exec /bin/sh --login
```

  04) What if I want a binary in the initrd, but libraries are missing?

  That is a bit tricky.  One option is to compile statically, but that
  does not work for everything.  Debian puts some libraries into lib/ and
  lib64/ which are usually enough.  If you need more, you can add the
  libraries you need there.  That may or may not need a configuration
  change for the dynamic linker "ld" as well.  Refer to standard Linux
  documentation on how to add a library to a Linux system.  A running
  initrd is just a running Linux system after all, it is not special in
  any way.

  05) How do I repack the initrd?

  Simply repack the changed directory. While in tmp/, do
  the following:
  ```
  find . | cpio --create --format='newc' | gzip > ../new_initrd
  ```
  Rename "new_initrd" to however you want it called (the name of
  the initrd is a kernel-parameter) and move to /boot. That is it.


# 10. LUKS2 Questions


  * **10.1 Is the cryptography of LUKS2 different?**

  Mostly not.  The header has changed in its structure, but the
  cryptography is the same.  The one exception is that PBKDF2 has been
  replaced by Argon2 to give better resilience against attacks by
  graphics cards and other hardware with lots of computing power but
  limited local memory per computing element.


  * **10.2 What new features does LUKS2 have?**
  
  There are quite a few.  I recommend reading the man-page and the on-disk
  format specification, see Item 1.2.

  To list just some:
  - A lot of the metadata is JSON, allowing for easier extension
  - Max 32 key-slots per default
  - Better protection for bad passphrases now available with Argon2
  - Authenticated encryption 
  - The LUKS2 header is less vulnerable to corruption and has a 2nd copy
  
  
  * **10.3 Why does LUKS2 need so much memory?**

  LUKS2 uses Argon2 instead of PBKDF2.  That causes the increase in memory. 
  See next item.


  * **10.4  Why use Argon2 in LUKS 2 instead of PBKDF2?**

  LUKS tries to be secure with not-so-good passwords.  Bad passwords need to
  be protected in some way against an attacker that just tries all possible
  combinations.  (For good passwords, you can just wait for the attacker to
  die of old age...) The situation with LUKS is not quite the same as with a
  password stored in a database, but there are similarities.

  LUKS does not store passwords on disk.  Instead, the passwords are used to
  decrypt the volume-key with it and that one is stored on disk in encrypted
  form.  If you have a good password, with, say, more than 80 bits of
  entropy, you could just put the password through a single crypto-hash (to
  turn it into something that can be used as a key) and that would be secure. 
  This is what plain dm-crypt does.

  If the password has lower entropy, you want to make this process cost some
  effort, so that each try takes time and resources and slows the attacker
  down.  LUKS1 uses PBKDF2 for that, adding an iteration count and a salt. 
  The iteration count is per default set to that it takes 1 second per try on
  the CPU of the device where the respective passphrase was set.  The salt is
  there to prevent precomputation.

  The problem with that is that if you use a graphics card, you can massively
  speed up these computations as PBKDF2 needs very little memory to compute
  it.  A graphics card is (grossly simplified) a mass of small CPUs with some
  small very fast local memory per CPU and a large slow memory (the 4/6/8 GB
  a current card may have).  If you can keep a computation in the small,
  CPU-local memory, you can gain a speed factor of 1000 or more when trying
  passwords with PBKDF2.

  Argon2 was created to address this problem.  It adds a "large memory
  property" where computing the result with less memory than the memory
  parameter requires is massively (exponentially) slowed down.  That means,
  if you set, for example, 4GB of memory, computing Argon2 on a graphics card
  with around 100kB of memory per "CPU" makes no sense at all because it is
  far too slow.  An attacker has hence to use real CPUs and furthermore is
  limited by main memory bandwidth.

  Hence the large amount of memory used is a security feature and should not
  be turned off or reduced.  If you really (!) understand what you are doing
  and can assure good passwords, you can either go back to PBKDF2 or set a
  low amount of memory used for Argon2 when creating the header.


  * **10.5 LUKS2 is insecure! It uses less memory than the Argon2 RFC say!**

  Well, not really.  The RFC recommends 6GiB of memory for use with disk
  encryption.  That is a bit insane and something clearly went wrong in the
  standardization process here.  First, that makes Argon2 unusable on any 32
  bit Linux and that is clearly a bad thing.  Second, there are many small
  Linux devices around that do not have 6GiB of RAM in the first place.  For
  example, the current Raspberry Pi has 1GB, 2GB or 4GB of RAM, and with the
  RFC recommendations, none of these could compute Argon2 hashes.

  Hence LUKS2 uses a more real-world approach.  Iteration is set to a
  minimum of 4 because there are some theoretical attacks that work up to an
  iteration count of 3.  The thread parameter is set to 4.  To achieve 2
  second/slot unlock time, LUKS2 adjusts the memory parameter down if
  needed.  In the other direction, it will respect available memory and not
  exceed it.  On a current PC, the memory parameter will be somewhere around
  1GB, which should be quite generous.  The minimum I was able to set in an
  experiment with "-i 1" was 400kB of memory and that is too low to be
  secure.  A Raspberry Pi would probably end up somewhere around 50MB (have
  not tried it) and that should still be plenty.

  That said, if you have a good, high-entropy passphrase, LUKS2 is secure
  with any memory parameter.


  * **10.6 How does re-encryption store data while it is running?**

  All metadata necessary to perform a recovery of said segment (in case of 
  crash) is stored in the LUKS2 metadata area. No matter if the LUKS2 
  reencryption was run in online or offline mode.

  
  * **10.7 What do I do if re-encryption crashes?**
  
  In case of a reencryption application crash, try to close the original
  device via following command first: 
```
    cryptsetup close <my_crypt_device>. 
```
  Cryptsetup assesses if it's safe to teardown the reencryption device stack
  or not.  It will also cut off I/O (via dm-error mapping) to current
  hotzone segment (to make later recovery possible).  If it can't be torn
  down, i.e.  due to a mounted fs, you must unmount the filesystem first. 
  Never try to tear down reencryption dm devices manually using e.g. 
  dmsetup tool, at least not unless cryptsetup says it's safe to do so.  It
  could damage the data beyond repair.


  * **10.8 Do I need to enter two passphrases to recover a crashed re-encryption?** 

  Cryptsetup (command line utility) expects the passphrases to be identical
  for the keyslot containing old volume key and for the keyslot containing
  new one.  So the recovery happens during normal the "cryptsetup open" 
  operation or the equivalent during boot.

  Re-encryption recovery can be also performed in offline mode by 
  the "cryptsetup repair" command.


  * **10.9 What is an unbound keyslot and what is it used for?**

  Quite simply, an 'unbound key' is an independent 'key' stored in a luks2 
  keyslot that cannot be used to unlock a LUKS2 data device. More specifically, 
  an 'unbound key' or 'unbound luks2 keyslot' contains a secret that is not
  currently associated with any data/crypt segment (encrypted area) in the 
  LUKS2 'Segments' section (displayed by luksDump).

  This is a bit of a more general idea. It basically allows one to use a
  keyslot as a container for a key to be used in other things than decrypting
  a data segment.

  As of April 2020, the following uses are defined:

  1) LUKS2 re-encryption. The new volume key is stored in an unbound keyslot 
     which becomes a regular LUKS2 keyslot later when re-encryption is 
     finished.
  
  2) Somewhat similar is the use with a wrapped key scheme (e.g. with the 
     paes cipher). In this case, the VK (Volume Key) stored in a keyslot 
     is an encrypted binary binary blob. The KEK (Key Encryption Key) for 
     that blob may be refreshed (Note that this KEK is not managed by 
     cryptsetup!) and the binary blob gets changed. The KEK refresh process 
     uses an 'unbound keyslot'. First the future effective VK is placed 
     in the unbound keyslot and later it gets turned into the new real VK 
     (and bound to the respective crypt segment).


  * **10.10 What about the size of the LUKS2 header**?

  While the LUKS1 header has a fixed size that is determined by the cipher
  spec (see Item 6.12), LUKS2 is more variable. The default size is 16MB,
  but it can be adjusted on creation by using the --luks2-metadata-size 
  and --luks2-keyslots-size options. Refer to the man-page for details.
  While adjusting the size in an existing LUKS2 container is possible,
  it is somewhat complicated and risky. My advice is to do a backup, 
  recreate the container with changed parameters and restore that backup.


  * **10.11 Does LUKS2 store metadata anywhere except in the header?**
 
  It does not. But note that if you use the experimental integrity support,
  there will be an integrity header as well at the start of the data area 
  and things  get a bit more complicated. All metadata will still be at the 
  start of the device, nothing gets stored somewhere in the middle or at 
  the end. 
  
  * **10.12 What is a LUKS2 Token?**

  A LUKS2 token is an object that describes "how to get a passphrase or 
  key" to unlock particular keyslot. A LUKS2 token is stored as json data 
  in the LUKS2 header. The token can be related to all keyslots or a 
  specific one. As the token is stored in JSON formay it is text by 
  default but binary data can be encoded into it according to the JSON 
  conventions.
 
  Documentation on the last changes to LUKS2 tokens can be found in the 
  release notes. As of version 2.4 of cryptsetup, there are significant 
  features. The standard documentation for working with tokens is 
  in the luks2 reference available as PDF on the project page.


# 11. References and Further Reading


  * **Purpose of this Section**

  The purpose of this section is to collect references to all materials
  that do not fit the FAQ but are relevant in some fashion.  This can be
  core topics like the LUKS spec or disk encryption, but it can also be
  more tangential, like secure storage management or cryptography used in
  LUKS.  It should still have relevance to cryptsetup and its
  applications.

  If you want to see something added here, send email to the maintainer
  (or the cryptsetup mailing list) giving an URL, a description (1-3 lines
  preferred) and a section to put it in.  You can also propose new
  sections.

  At this time I would like to limit the references to things that are
  available on the web.

  * **Specifications**

  - LUKS on-disk format spec: See Item 1.2

  * **Other Documentation**
  
  - Arch Linux on LUKS, LVM and full-disk encryption: 
    https://wiki.archlinux.org/index.php/Dm-crypt/Encrypting_an_entire_system

  * **Code Examples**

  - Some code examples are in the source package under docs/examples

  - LUKS AF Splitter in Ruby by John Lane: https://rubygems.org/gems/afsplitter

  * **Brute-forcing passphrases**

  - http://news.electricalchemy.net/2009/10/password-cracking-in-cloud-part-5.html

  - https://it.slashdot.org/story/12/12/05/0623215/new-25-gpu-monster-devours-strong-passwords-in-minutes

  * **Tools**

  * **SSD and Flash Disk Related**

  * **Disk Encryption**

  * **Attacks Against Disk Encryption**

  * **Risk Management as Relevant for Disk Encryption**

  * **Cryptography**

  * **Secure Storage**


# A. Contributors
In no particular order:

  - Arno Wagner

  - Milan Broz

___
