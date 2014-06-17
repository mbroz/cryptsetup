#!/usr/bin/python
#
# Python bindings to libcryptsetup test
#
# Copyright (C) 2011-2014, Red Hat, Inc. All rights reserved.
#
# This file is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This file is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this file; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

from __future__ import print_function

import sys
import os

sys.path.insert(0, ".libs")
import pycryptsetup

IMG = "test.img"
PASSWORD = "password"
PASSWORD2 = "password2"
DEVICE = "pycryptsetup_test_dev"

def log(level, txt):
    if level == pycryptsetup.CRYPT_LOG_ERROR:
        print(txt,end="")
    return

def askyes(txt):
    print("Question:", txt)
    return 1

def askpassword(txt):
    return PASSWORD

def print_status(c):
    r = c.status()
    print("status  :",end="")
    if r == pycryptsetup.CRYPT_ACTIVE:
        print("ACTIVE")
    elif r == pycryptsetup.CRYPT_INACTIVE:
        print("INACTIVE")
    else:
       print("ERROR")
    return

if os.geteuid() != 0:
	print("WARNING: You must be root to run this test, test skipped.")
	sys.exit(0)

os.system("dd if=/dev/zero of=" + IMG + " bs=1M count=32 >/dev/null 2>&1")

c = pycryptsetup.CryptSetup(
        device = IMG,
        name = DEVICE,
        yesDialog = askyes,
        logFunc = log,
        passwordDialog = askpassword)

#c.debugLevel(pycryptsetup.CRYPT_DEBUG_ALL);
c.debugLevel(pycryptsetup.CRYPT_DEBUG_NONE);
c.iterationTime(1)
r =  c.isLuks()
print("isLuks  :", r)
c.askyes(message = "Is there anybody out there?")
c.log(priority = pycryptsetup.CRYPT_LOG_ERROR, message = "Nobody there...\n")
c.luksFormat(cipher = "aes", cipherMode= "xts-plain64", keysize = 512)
print("isLuks  :", c.isLuks())
print("luksUUID:", c.luksUUID())
print("addKeyVK:", c.addKeyByVolumeKey(newPassphrase = PASSWORD, slot = 2))
print("addKeyP :", c.addKeyByPassphrase(passphrase = PASSWORD,
					newPassphrase = PASSWORD2, slot = 3))
print("removeP :", c.removePassphrase(passphrase = PASSWORD2))
print("addKeyP :", c.addKeyByPassphrase(PASSWORD, PASSWORD2))
# original api required wrong passphrase parameter here
# print "killSlot:", c.killSlot(passphrase = "xxx", slot = 0)
print("killSlot:", c.killSlot(slot = 0))
print("activate:", c.activate(name = DEVICE, passphrase = PASSWORD))
print("suspend :", c.suspend())
# os.system("dmsetup info -c " + DEVICE)
print("resume  :", c.resume(passphrase = PASSWORD))
print_status(c)
info = c.info()
print("cipher  :", info["cipher"])
print("cmode   :", info["cipher_mode"])
print("keysize :", info["keysize"])
print("dir     :", info["dir"])
print("device  :", info["device"])
print("offset  :", info["offset"])
print("name    :", info["name"])
print("uuid    :", info["uuid"])
# os.system("cryptsetup luksDump " + info["device"])
print("deact.  :", c.deactivate())

del c

c = pycryptsetup.CryptSetup(
        device = IMG,
        name = DEVICE,
        yesDialog = askyes,
        logFunc = log,
        passwordDialog = askpassword)

print("activate:", c.activate(name = DEVICE, passphrase = PASSWORD))

c2 = pycryptsetup.CryptSetup(
        name = DEVICE,
        yesDialog = askyes,
        logFunc = log,
        passwordDialog = askpassword)

info = c2.info()
print("cipher  :", info["cipher"])
print("cmode   :", info["cipher_mode"])
print("keysize :", info["keysize"])

print("deact.  :", c.deactivate())
r = c2.deactivate()
print("deact.  :", r)
del c
del c2

os.remove(IMG)
