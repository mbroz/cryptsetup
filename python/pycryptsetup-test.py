#!/usr/bin/python

import sys
import os

sys.path.insert(0, ".libs")
import pycryptsetup

IMG = "test.img"
PASSWORD = "password"
PASSWORD2 = "password2"
DEVICE = "pycryptsetup_test_dev"

def log(pri, txt):
    if pri > 1:
        return
    print txt,
    return

def askyes(txt):
    print "Question:", txt
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

# c.debugLevel(-1);
c.debugLevel(0);
c.iterationTime(1)
r =  c.isLuks()
print "isLuks  :", r
c.askyes(message = "Is there anybody out there?")
c.log(priority = 1, message = "Nobody there...\n")
c.luksFormat(cipher = "aes", cipherMode= "xts-plain64", keysize = 512)
print "isLuks  :", c.isLuks()
print "luksUUID:", c.luksUUID()
print "addKeyVK:", c.addKeyByVolumeKey(newPassphrase = PASSWORD, slot = 2)
print "addKeyP :", c.addKeyByPassphrase(passphrase = PASSWORD,
					newPassphrase = PASSWORD2, slot = 3)
print "removeP :", c.removePassphrase(passphrase = PASSWORD2)
print "addKeyP :", c.addKeyByPassphrase(PASSWORD, PASSWORD2)
# original api required wrong passphrase paramater here
# print "killSlot:", c.killSlot(passphrase = "xxx", slot = 0)
print "killSlot:", c.killSlot(slot = 0)
print "activate:", c.activate(name = DEVICE, passphrase = PASSWORD)
print "suspend :", c.suspend()
# os.system("dmsetup info -c " + DEVICE)
print "resume  :", c.resume(passphrase = PASSWORD)
print "status  :", c.status()
info = c.info()
print "cipher  :", info["cipher"]
print "cmode   :", info["cipher_mode"]
print "keysize :", info["keysize"]
print "dir     :", info["dir"]
print "device  :", info["device"]
print "offset  :", info["offset"]
print "name    :", info["name"]
print "uuid    :", info["uuid"]
# os.system("cryptsetup luksDump " + info["device"])
print "deact.  :", c.deactivate()

del c

os.remove(IMG)
