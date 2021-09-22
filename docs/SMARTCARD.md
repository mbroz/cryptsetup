# cryptsetup with smartcard

This extension to cryptsetup adds smartcard support by securely storing the information needed to decrypt in the LUKS2 header.

# history

Traditionally, the use of smartcards with LUKS requires storing an encrypted key in a file.  This file must be maintained separately from the LUKS container.

This is difficult to manage as it requires a separate location to host the file and makes the process more complicated.  With the addition of json metadata with LUKS2 we may now store the information in the luks container.  

* removes need for separate file
 + no longer depends on another filesystem or data source for keys
* reduces complexity

# requirements

* gpg
* LUKS2

# status

* user space utilities
* regression tests included

# future plans

* create C based cryptsetup plugin
* man pages

# usage

For details use -h with scripts. 

  cryptsetup-smartcard -h

Assuming we have gpg working and cryptsetup installed....  First, we have to add the smartcard based key to our LUKS container (new or existing).  Then, we use the handle script to decrypt the container.

## Setup

The simplest case is to create a new container using the default settings.  This can be done interactively or in batch mode.  In this model, there is a passphrase added to keyslot 0 and a large binary key added to keyslot 1.  The binary key is protected by the smartcard.  Make sure the smartcard is plugged in and gpg is setup to use it.

  cryptsetup-smartcard /dev/whatever init

## Decrypt

Now we decrypt the LUKS container using the smartcard.  The device is specified and which token we are using (in this case 0). If we want to specify the decrypted device we add the -n option.

  tokens/smartcard/handle-token.sh /dev/whatever 0 -n myOpenContainer

This will result in a device /dev/mapper/myOpenContainer which you may use as a normal block device.

# Files

cryptsetup-smartcard
tokens/smartcard/handle-token.sh
tests/smartcard/*
docs/SMARTCARD.md
