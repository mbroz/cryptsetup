#!/usr/bin/python

import sys
import os

sys.path.insert(0, ".libs")
import pycryptsetup

IMG = "test.img"
PASSWORD = "password"
DEVICE = "pycryptsetup_test_dev"

def log(pri, txt):
    if pri > 1:
        return
    print txt,
    return

def askyes(txt):
    print "Asking about:", txt, "\n"
    return 1

def askpassword(txt):
    return PASSWORD

os.system("dd if=/dev/zero of=" + IMG + " bs=1M count=32 >/dev/null 2>&1")

c = pycryptsetup.CryptSetup(
        device = IMG,
        name = DEVICE,
        yesDialog = askyes,
        logFunc = log,
        passwordDialog = askpassword)

r =  c.isLuks()
print "isLuks  :", r
c.luksFormat()
print "isLuks  :", c.isLuks()
print "luksUUID:", c.luksUUID()
print "addKey  :", c.addKeyByVolumeKey(PASSWORD)
print "activate:", c.activate(name = DEVICE, passphrase = PASSWORD)
print "status  :", c.status()
info = c.info()
print "cipher  :", info["cipher"]
print "cmode   :", info["cipher_mode"]
print "deact.  :", c.deactivate()

del c

os.remove(IMG)
