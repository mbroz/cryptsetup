#!/bin/bash

#set -x
# Author: JT Moree
# License:  same as cryptsetup

#### TODO ####

# * tests for handle_token.sh

cleanup() {
    if [ -f "$BDEV" ] ; then
        rm -rf $BDEV
    fi
    if [ -f "$PASSPHRASE_FILE" ] ; then
        rm -rf PASSPHRASE_FILE
    fi
    if [ -f "$LOG" ] ; then
        echo LOG AT $LOG
    fi
}

function die() {
    cleanup
    echo "$2" >&2
    exit $1
}

function prep-sudo() {
    export SUDO='sudo'
    $SUDO whoami >> $LOG
}

function check-depends() {
    if [ -z "`which gpg`" ] ; then
        die 200 "missing dependency 'gpg'"
    fi
    if [ -z "$PUBLIC_KEYFILE" ] && [ "$PUBLIC_KEYFILE" != 'none' ] ; then
        die 201 "No public key file specified.  You must specify the public key that goes with your gpg key used for testing or specify 'none' to skip those tests.  ex.  cryptsetup-sc-test /path/to/key"
    fi
    if [ -z "`which expect`" ] ; then
        echo "expect command not found.  Some tests will be skipped"
        EXPECT=no
    fi
}

PUBLIC_KEYFILE=$1
CRYPTSETUP=./cryptsetup
SC=./cryptsetup-smartcard
CRYPTSETUP_OPTS=" --pbkdf-memory 32 "
HANDLE=./tokens/smartcard/handle-token.sh
MAPPER=/dev/mapper
EXPECT="yes"

LOG=`mktemp`

PASSPHRASE_FILE=`mktemp`
echo "PASSPHRASE" >> $PASSPHRASE_FILE

prep-sudo
check-depends

FAILED=0
TESTS=0
SUCCESS=0
SKIPPED=0


############################# CRYPTSETUP-SC TESTS #############################

TESTS=$(($TESTS + 1))
S=
TESTNAME="check block device"
R=$(
    echo "###########################"  >> $LOG; echo $TESTNAME >> $LOG
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    test -b $BDEV
    echo $?
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"


TESTS=$(($TESTS + 1))
S=
TESTNAME="check gpg"
R=$(
    echo "###########################"  >> $LOG; echo $TESTNAME >> $LOG
    T=`mktemp`
    echo "TEST" > $T
    gpg --armor --default-recipient-self --trust-model=always --yes --encrypt -o $T.asc $T
    echo $?
)
if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"


TESTS=$(($TESTS + 1))
S=
TESTNAME="test -h"
R=$(
    echo "###########################"  >> $LOG; echo $TESTNAME >> $LOG
    OUTPUT=`$SC -h 2>> $LOG`
    echo $?
)
if [ "$R" = "1" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"



TESTS=$(($TESTS + 1))
S=
TESTNAME="invalid block device"
R=$(
    echo "###########################"  >> $LOG; echo $TESTNAME >> $LOG
    $SC /dev/doesNOTexist add -t -b  2>> $LOG 1>> $LOG
    X=$?
    echo $X
)
if [ "$R" != "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"


TESTS=$(($TESTS + 1))
S=
TESTNAME="invalid mode"
R=$(
    echo "###########################"  >> $LOG; echo $TESTNAME >> $LOG
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    $SC $BDEV foo -b -f $PASSPHRASE_FILE  2>>$LOG >> $LOG
    echo $?
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" != "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"

TESTS=$(($TESTS + 1))
S=
TESTNAME="block device is not luks"
R=$(
    echo "###########################"  >> $LOG; echo $TESTNAME >> $LOG
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    $SC $BDEV add -p -b -f $PASSPHRASE_FILE  2>>$LOG >> $LOG
    echo $?
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" != "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"

TESTS=$(($TESTS + 1))
S=
TESTNAME="batch mode without passphrase"
R=$(
    echo "###########################"  >> $LOG; echo $TESTNAME >> $LOG
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    $SC $BDEV add -p -b -k 0 2>>$LOG >> $LOG
    echo $?
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" != "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"

TESTS=$(($TESTS + 1))
S=
TESTNAME="batch mode with passphrase missing keyslot"
R=$(
    echo "###########################"  >> $LOG; echo $TESTNAME >> $LOG
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    $SC $BDEV add -p -b -f $PASSPHRASE_FILE 2>>$LOG >> $LOG
    echo $?
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" != "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"

TESTS=$(($TESTS + 1))
S=
TESTNAME="init luks device using only passphrase"
R=$(
    #create a block device for testing
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    echo "###########################"  >> $LOG; echo $TESTNAME >> $LOG
    $SUDO $CRYPTSETUP $CRYPTSETUP_OPTS luksFormat $BDEV --disable-locks --batch-mode --key-file=$PASSPHRASE_FILE 2>>$LOG >> $LOG
    echo $?
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"

TESTS=$(($TESTS + 1))
S=
TESTNAME="init luks device using passphrase and smartcard"
R=$(
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    echo "###########################"  >> $LOG; echo $TESTNAME >> $LOG
    $SC $BDEV init -p -b -f $PASSPHRASE_FILE 2>>$LOG 1>> $LOG
    echo $?
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"

TESTS=$(($TESTS + 1))
S=
TESTNAME="init luks device using SUDO"
R=$(
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    echo "###########################"  >> $LOG; echo $TESTNAME >> $LOG
    $SC $BDEV init -S -p -b -f $PASSPHRASE_FILE 2>>$LOG 1>> $LOG
    echo $?
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"



TESTS=$(($TESTS + 1))
S=
TESTNAME="init luks device with passphrase, key, and smartcard"
R=$(
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    echo "###########################"  >> $LOG; echo $TESTNAME >> $LOG
    $SC $BDEV init -b -f $PASSPHRASE_FILE 2>>$LOG 1>> $LOG
    if [ "$?" = "0" ] ; then
        SUBTYPE=`$SUDO $CRYPTSETUP token export $BDEV --token-id 0 --disable-locks | jq .subtype| tr -d '"'` 2>>$LOG >> $LOG
        if [ "$SUBTYPE" = "gpg" ] ; then
            echo 0
        else 
            echo "BAD SUBTYPE" >>$LOG
            echo 1
        fi
    else
        echo $?
    fi
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"


TESTS=$(($TESTS + 1))
S=
TESTNAME="add smartcard to existing luks device with passphrase only"
R=$(
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    echo "###########################"  >> $LOG; echo $TESTNAME >> $LOG
    $SUDO $CRYPTSETUP $CRYPTSETUP_OPTS luksFormat $BDEV --disable-locks --batch-mode --key-file=$PASSPHRASE_FILE 2>>$LOG >> $LOG
    if [ "$?" = "0" ] ; then
        $SC $BDEV add -b -p -k 0 -f $PASSPHRASE_FILE 2>>$LOG >> $LOG
        X=$?
        if [ "$X" = "0" ] ; then
            SUBTYPE=`$SUDO $CRYPTSETUP token export $BDEV --token-id 0 --disable-locks | jq .subtype| tr -d '"'` 2>>$LOG >> $LOG
            if [ "$SUBTYPE" = "gpg" ] ; then
                echo 0
            else 
                echo "BAD SUBTYPE" >>$LOG
                echo 1
            fi
        else
            echo $X
        fi
    else
        echo $?
    fi
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"

TESTS=$(($TESTS + 1))
S=
TESTNAME="add key and smartcard to existing luks device"
R=$(
    echo "###########################"  >> $LOG; echo $TESTNAME >> $LOG
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    $SUDO $CRYPTSETUP $CRYPTSETUP_OPTS luksFormat $BDEV --disable-locks --batch-mode --key-file=$PASSPHRASE_FILE 2>>$LOG >> $LOG
    if [ "$?" = "0" ] ; then
        $SC $BDEV add -b -f $PASSPHRASE_FILE 2>>$LOG >> $LOG
        X=$?
        if [ "$X" = "0" ] ; then
            SUBTYPE=`$SUDO $CRYPTSETUP token export $BDEV --token-id 0 --disable-locks | jq .subtype | tr -d '"'` 2>>$LOG >> $LOG
            if [ "$SUBTYPE" = "gpg" ] ; then
                echo 0
            else 
                echo "BAD SUBTYPE" >>$LOG
                echo 1
            fi
        else
            echo $X
        fi
    else
        echo $?
    fi
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"

TESTS=$(($TESTS + 1))
S=
TESTNAME="add key and smartcard using SUDO"
R=$(
    echo "###########################"  >> $LOG; echo $TESTNAME >> $LOG
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    $SUDO $CRYPTSETUP $CRYPTSETUP_OPTS luksFormat $BDEV --disable-locks --batch-mode --key-file=$PASSPHRASE_FILE 2>>$LOG >> $LOG
    if [ "$?" = "0" ] ; then
        $SC $BDEV add -b -S -f $PASSPHRASE_FILE 2>>$LOG >> $LOG
        X=$?
        if [ "$X" = "0" ] ; then
            SUBTYPE=`$SUDO $CRYPTSETUP token export $BDEV --token-id 0 --disable-locks | jq .subtype | tr -d '"'` 2>>$LOG >> $LOG
            if [ "$SUBTYPE" = "gpg" ] ; then
                echo 0
            else 
                echo "BAD SUBTYPE" >>$LOG
                echo 1
            fi
        else
            echo $X
        fi
    else
        echo $?
    fi
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"


TESTS=$(($TESTS + 1))
S=
TESTNAME="add key and smartcard to existing luks device with multiple existing keys"
R=$(
    echo $TESTNAME >> $LOG
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    KEY2=`mktemp`
    dd if=/dev/urandom of=$KEY2 bs=256 count=1 2>/dev/null 1>/dev/null
    KEY3=`mktemp`
    dd if=/dev/urandom of=$KEY3 bs=256 count=1 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    $SUDO $CRYPTSETUP $CRYPTSETUP_OPTS luksFormat $BDEV --disable-locks --batch-mode --key-file=$PASSPHRASE_FILE 2>>$LOG >> $LOG
    if [ "$?" = "0" ] ; then
        $SUDO $CRYPTSETUP $CRYPTSETUP_OPTS luksAddKey $BDEV --disable-locks --batch-mode --key-file=$PASSPHRASE_FILE $KEY2 2>>$LOG >> $LOG
        rm -rf $KEY2
        $SUDO $CRYPTSETUP $CRYPTSETUP_OPTS luksAddKey $BDEV --disable-locks --batch-mode --key-file=$PASSPHRASE_FILE $KEY3 2>>$LOG >> $LOG
        rm -rf $KEY3
        $SC $BDEV add -b -f $PASSPHRASE_FILE 2>>$LOG >> $LOG
        X=$?
        if [ "$X" = "0" ] ; then
            KSLOTS=`$SUDO $CRYPTSETUP token export $BDEV --token-id 0 --disable-locks | jq .keyslots | head -n -1 | tail -n -1 | tr -d '"' | tr -d ' '`
            echo "keyslots = '$KSLOTS'" >> $LOG
            if [ `echo $KSLOTS | wc -l` -eq 1 ] && [ "$KSLOTS" = "3" ] ; then
                echo 0
            else 
                echo "BAD KEYSLOT MAPPING" >>$LOG
                echo $KEYSLOTS >> $LOG
                echo 1
            fi
        else
            echo $X
        fi
    else
        echo $?
    fi
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"


TESTS=$(($TESTS + 1))
S=
TESTNAME="add key and smartcard to existing luks device in specific keyslot"
R=$(
    echo $TESTNAME >> $LOG
    SLOT=7
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    KEY2=`mktemp`
    dd if=/dev/urandom of=$KEY2 bs=256 count=1 2>/dev/null 1>/dev/null
    KEY3=`mktemp`
    dd if=/dev/urandom of=$KEY3 bs=256 count=1 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    $SUDO $CRYPTSETUP $CRYPTSETUP_OPTS luksFormat $BDEV --disable-locks --batch-mode --key-file=$PASSPHRASE_FILE 2>>$LOG >> $LOG
    if [ "$?" = "0" ] ; then
        $SUDO $CRYPTSETUP $CRYPTSETUP_OPTS luksAddKey $BDEV --disable-locks --batch-mode --key-file=$PASSPHRASE_FILE $KEY2 2>>$LOG >> $LOG
        rm -rf $KEY2
        $SUDO $CRYPTSETUP $CRYPTSETUP_OPTS luksAddKey $BDEV --disable-locks --batch-mode --key-file=$PASSPHRASE_FILE $KEY3 2>>$LOG >> $LOG
        rm -rf $KEY3
        $SC $BDEV add -b -f $PASSPHRASE_FILE -k $SLOT 2>>$LOG >> $LOG
        X=$?
        if [ "$X" = "0" ] ; then
            KSLOTS=`$SUDO $CRYPTSETUP token export $BDEV --token-id 0 --disable-locks | jq .keyslots | head -n -1 | tail -n -1 | tr -d '"' | tr -d ' '`
            echo "keyslots = '$KSLOTS'" >> $LOG
            if [ `echo $KSLOTS | wc -l` -eq 1 ] && [ "$KSLOTS" = "7" ] ; then
                echo 0
            else 
                echo "BAD KEYSLOT MAPPING" >>$LOG
                echo $KEYSLOTS >> $LOG
                echo 1
            fi
        else
            echo $X
        fi
    else
        echo $?
    fi
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"


TESTS=$(($TESTS + 1))
S=
TESTNAME="init luks device using invalid public key (non existing file)"
R=$(
    PKEY=`mktemp`
    if [ -f "$PKEY" ] ; then rm -rf $PKEY >> $LOG 2>>$LOG ; fi
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    echo $TESTNAME >> $LOG
    $SC $BDEV init -p -b -f $PASSPHRASE_FILE -P $PKEY 2>>$LOG 1>> $LOG
    echo $?
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" != "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"

TESTS=$(($TESTS + 1))
S=
TESTNAME="init luks device using invalid) public key (empty file)"
R=$(
    PKEY=`mktemp`
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    echo $TESTNAME >> $LOG
    $SC $BDEV init -p -b -f $PASSPHRASE_FILE -P $PKEY 2>>$LOG 1>> $LOG
    echo $?
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$PKEY" ] ; then rm -rf $PKEY >> $LOG 2>>$LOG ; fi
)
if [ "$R" != "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"

TESTS=$(($TESTS + 1))
S=
TESTNAME="init luks device using invalid public key (not gpg file)"
R=$(
    PKEY=`mktemp`
    echo "NOT A GPG FILE" > $PKEY
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    echo $TESTNAME >> $LOG
    $SC $BDEV init -p -b -f $PASSPHRASE_FILE -P $PKEY 2>>$LOG 1>> $LOG
    echo $?
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$PKEY" ] ; then rm -rf $PKEY >> $LOG 2>>$LOG ; fi
)
if [ "$R" != "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"


TESTS=$(($TESTS + 1))
S=
TESTNAME="init luks device using passphrase, smartcard, and public key"
if [ -n "$PUBLIC_KEYFILE" ] && [ -f "$PUBLIC_KEYFILE" ] ; then
    R=$(
        FDEV=`mktemp`
        dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
        $SUDO losetup -fP $FDEV
        BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
        echo $TESTNAME >> $LOG
        $SC $BDEV init -p -b -f $PASSPHRASE_FILE -P $PUBLIC_KEYFILE 2>>$LOG 1>> $LOG
        if [ "$?" = "0" ] ; then
            PUBLICKEY=`$SUDO $CRYPTSETUP token export $BDEV --token-id 0 --disable-locks | jq .public | tr -d '"'` 2>>$LOG >> $LOG
            if [ "$PUBLICKEY" != "" ] ; then
                echo 0
            else 
                echo "missing public key" >>$LOG
                echo 1
            fi
        else
            echo $?
        fi
        if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
        if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
    )
    if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
    printf "%s\t%s\n" "$S" "$TESTNAME"
else
    S="S"
    SKIPPED=$(($SKIPPED + 1))
    printf "%s\t%s\n" "$S" "$TESTNAME"
    echo "No public keyfile specified" >> $LOG
fi



############################# HANDLE TOKEN TESTS ##############################



TESTS=$(($TESTS + 1))
S=
TESTNAME="decrypt luks device using token linked to passphrase"
R=$(
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    echo "###########################"  >> $LOG; echo $TESTNAME >> $LOG
    $SC $BDEV init -b -p -f $PASSPHRASE_FILE 2>>$LOG 1>> $LOG
    if [ "$?" = "0" ] ; then
        $HANDLE $BDEV 0 -t 2>/dev/null 1>/dev/null
        echo $?
    else
        echo $?
    fi
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"




TESTS=$(($TESTS + 1))
S=
TESTNAME="decrypt luks device using token linked to binary key"
R=$(
    FDEV=`mktemp`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    echo "###########################"  >> $LOG; echo $TESTNAME >> $LOG
    $SC $BDEV init -b -f $PASSPHRASE_FILE 2>>$LOG 1>> $LOG
    if [ "$?" = "0" ] ; then
        $HANDLE $BDEV 0 -t 2>/dev/null 1>/dev/null
        echo $?
    else
        echo $?
    fi
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"




TESTS=$(($TESTS + 1))
S=
TESTNAME="decrypt luks device using custom device mapper name"
R=$(
    FDEV=`mktemp`
    TNAME=`basename $(mktemp -u )`
    dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
    $SUDO losetup -fP $FDEV
    BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
    echo $TESTNAME >> $LOG
    $SC $BDEV init -b -f $PASSPHRASE_FILE 2>>$LOG 1>> $LOG
    if [ "$?" = "0" ] ; then
        $HANDLE $BDEV 0 -n $TNAME 2>/dev/null 1>/dev/null
        if [ "$?" = "0" ] ; then
            if [ -b "${MAPPER}/${TNAME}" ] ; then
                echo 0
                $SUDO cryptsetup luksClose ${MAPPER}/${TNAME} >/dev/null 2>/dev/null
            else
                echo 1
            fi
        else
            echo $?
        fi
    else
        echo $?
    fi
    if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
    if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
)
if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
printf "%s\t%s\n" "$S" "$TESTNAME"



######################### INTERACTIVE TESTS ##########################


TESTS=$(($TESTS + 1))
S=
TESTNAME="interactive) init luks device using passphrase and smartcard"
echo "###########################"  >> $LOG
echo "# $TESTNAME" >> $LOG
if [ "$EXPECT" = "yes" ] ; then
    R=$(
        FDEV=`mktemp`
        dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
        $SUDO losetup -fP $FDEV
        BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
        tests/smartcard/init.exp $SC $BDEV init -f $PASSPHRASE_FILE "-p" 2>>$LOG 1>>$LOG
        R=$?
        echo $R
        if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
        if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
    )
    if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
else
    SKIPPED=$(($SKIPPED + 1))
    S="S"
fi
printf "%s\t%s\n" "$S" "$TESTNAME"


TESTS=$(($TESTS + 1))
S=
TESTNAME="interactive) init luks device with passphrase, key, and smartcard"
if [ "$EXPECT" = "yes" ] ; then
    R=$(
        FDEV=`mktemp`
        dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
        $SUDO losetup -fP $FDEV
        BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
        echo "###########################"  >> $LOG; echo "# $TESTNAME" >> $LOG
        tests/smartcard/init.exp $SC $BDEV init -f $PASSPHRASE_FILE 2>>$LOG 1>>$LOG
        R=$?
        if [ "$R" = "0" ] ; then
            SUBTYPE=`$SUDO $CRYPTSETUP token export $BDEV --token-id 0 --disable-locks | jq .subtype| tr -d '"'` 2>>$LOG >> $LOG
            if [ "$SUBTYPE" = "gpg" ] ; then
                R=0
            else 
                echo "BAD SUBTYPE" >>$LOG
                R=1
            fi
            echo $R
        fi
        if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
        if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
    )
    if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
else
    SKIPPED=$(($SKIPPED + 1))
    S="S"
fi
printf "%s\t%s\n" "$S" "$TESTNAME"



TESTS=$(($TESTS + 1))
S=
TESTNAME="interactive) add smartcard to existing luks device with passphrase only"
echo "###########################"  >> $LOG; echo "# $TESTNAME" >> $LOG
if [ "$EXPECT" = "yes" ] ; then
    R=$(
        FDEV=`mktemp`
        dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
        $SUDO losetup -fP $FDEV
        BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
        $SUDO $CRYPTSETUP $CRYPTSETUP_OPTS luksFormat $BDEV --disable-locks --batch-mode --key-file=$PASSPHRASE_FILE 2>>$LOG >> $LOG
        R=$?
        if [ "$R" = "0" ] ; then
            tests/smartcard/add.exp $SC $BDEV add -p -k 0 -f $PASSPHRASE_FILE 2>>$LOG 1>>$LOG
            R=$?
            if [ "$R" = "0" ] ; then
                SUBTYPE=`$SUDO $CRYPTSETUP token export $BDEV --token-id 0 --disable-locks | jq .subtype| tr -d '"'` 2>>$LOG >> $LOG
                if [ "$SUBTYPE" = "gpg" ] ; then
                    R=0
                else 
                    echo "BAD SUBTYPE" >>$LOG
                    R=1
                fi
                echo $R
            fi
        fi
        if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
        if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
    )
    if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
else
    SKIPPED=$(($SKIPPED + 1))
    S="S"
fi
printf "%s\t%s\n" "$S" "$TESTNAME"



TESTS=$(($TESTS + 1))
S=
TESTNAME="interactive) add key and smartcard to existing luks device using passphrase file"
echo "###########################"  >> $LOG; echo "# $TESTNAME" >> $LOG
if [ "$EXPECT" = "yes" ] ; then
    R=$(
        FDEV=`mktemp`
        dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
        $SUDO losetup -fP $FDEV
        BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
        $SUDO $CRYPTSETUP $CRYPTSETUP_OPTS luksFormat $BDEV --disable-locks --batch-mode --key-file=$PASSPHRASE_FILE 2>>$LOG >> $LOG
        R=$?
        if [ "$R" = "0" ] ; then
            tests/smartcard/add.exp $SC $BDEV add -f $PASSPHRASE_FILE 2>>$LOG 1>>$LOG
            R=$?
            if [ "$R" = "0" ] ; then
                SUBTYPE=`$SUDO $CRYPTSETUP token export $BDEV --token-id 0 --disable-locks | jq .subtype | tr -d '"'` 2>>$LOG >> $LOG
                if [ "$SUBTYPE" = "gpg" ] ; then
                    R=0
                else 
                    echo "BAD SUBTYPE" >>$LOG
                    R=1
                fi
                echo $R
            fi
        fi
        if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
        if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
    )
    if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
else
    SKIPPED=$(($SKIPPED + 1))
    S="S"
fi
printf "%s\t%s\n" "$S" "$TESTNAME"



TESTS=$(($TESTS + 1))
S=
TESTNAME="interactive) add key and smartcard to existing luks device using passphrase"
echo "###########################"  >> $LOG; echo "# $TESTNAME" >> $LOG
if [ "$EXPECT" = "yes" ] ; then
    R=$(
        FDEV=`mktemp`
        dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
        $SUDO losetup -fP $FDEV
        BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
        $SUDO $CRYPTSETUP $CRYPTSETUP_OPTS luksFormat $BDEV --disable-locks --batch-mode --key-file=$PASSPHRASE_FILE 2>>$LOG >> $LOG
        R=$?
        if [ "$R" = "0" ] ; then
            tests/smartcard/add_pass.exp $SC $BDEV add 2>>$LOG 1>>$LOG
            R=$?
            if [ "$R" = "0" ] ; then
                SUBTYPE=`$SUDO $CRYPTSETUP token export $BDEV --token-id 0 --disable-locks | jq .subtype | tr -d '"'` 2>>$LOG >> $LOG
                if [ "$SUBTYPE" = "gpg" ] ; then
                    R=0
                else 
                    echo "BAD SUBTYPE" >>$LOG
                    R=1
                fi
                echo $R
            fi
        fi
        if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
        if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
    )
    if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
else
    SKIPPED=$(($SKIPPED + 1))
    S="S"
fi
printf "%s\t%s\n" "$S" "$TESTNAME"




TESTS=$(($TESTS + 1))
S=
TESTNAME="interactive) add key and smartcard using SUDO"
echo "###########################"  >> $LOG; echo "# $TESTNAME" >> $LOG
if [ "$EXPECT" = "yes" ] ; then
    R=$(
        FDEV=`mktemp`
        dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
        $SUDO losetup -fP $FDEV
        BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
        $SUDO $CRYPTSETUP $CRYPTSETUP_OPTS luksFormat $BDEV --disable-locks --batch-mode --key-file=$PASSPHRASE_FILE 2>>$LOG >> $LOG
        R=$?
        if [ "$R" = "0" ] ; then
            #$SC $BDEV add -S -f $PASSPHRASE_FILE 2>>$LOG 
            tests/smartcard/add.exp $SC $BDEV add -f $PASSPHRASE_FILE -S 2>>$LOG 1>>$LOG
            R=$?
            if [ "$R" = "0" ] ; then
                SUBTYPE=`$SUDO $CRYPTSETUP token export $BDEV --token-id 0 --disable-locks | jq .subtype | tr -d '"'` 2>>$LOG >> $LOG
                if [ "$SUBTYPE" = "gpg" ] ; then
                    R=0
                else 
                    echo "BAD SUBTYPE" >>$LOG
                    R=1
                fi
                echo $R
            fi
        fi
        if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
        if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
    )
    if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
else
    SKIPPED=$(($SKIPPED + 1))
    S="S"
fi
printf "%s\t%s\n" "$S" "$TESTNAME"


TESTS=$(($TESTS + 1))
S=
TESTNAME="interactive) add key and smartcard to existing luks device with multiple existing keys"
echo "# $TESTNAME" >> $LOG
if [ "$EXPECT" = "yes" ] ; then
    R=$(
        FDEV=`mktemp`
        dd if=/dev/zero of=$FDEV bs=100M count=2 2>/dev/null 1>/dev/null
        KEY2=`mktemp`
        dd if=/dev/urandom of=$KEY2 bs=256 count=1 2>/dev/null 1>/dev/null
        KEY3=`mktemp`
        dd if=/dev/urandom of=$KEY3 bs=256 count=1 2>/dev/null 1>/dev/null
        $SUDO losetup -fP $FDEV
        BDEV=`losetup -j $FDEV | awk -F: '{print $1;}'`
        $SUDO $CRYPTSETUP $CRYPTSETUP_OPTS luksFormat $BDEV --disable-locks --batch-mode --key-file=$PASSPHRASE_FILE 2>>$LOG >> $LOG
        R=$?
        if [ "$R" = "0" ] ; then
            $SUDO $CRYPTSETUP $CRYPTSETUP_OPTS luksAddKey $BDEV --disable-locks --batch-mode --key-file=$PASSPHRASE_FILE $KEY2 2>>$LOG >> $LOG
            rm -rf $KEY2
            $SUDO $CRYPTSETUP $CRYPTSETUP_OPTS luksAddKey $BDEV --disable-locks --batch-mode --key-file=$PASSPHRASE_FILE $KEY3 2>>$LOG >> $LOG
            rm -rf $KEY3
            #$SC $BDEV add -f $PASSPHRASE_FILE 2>>$LOG 
            tests/smartcard/add.exp $SC $BDEV add -f $PASSPHRASE_FILE 2>>$LOG 1>>$LOG
            R=$?
            if [ "$R" = "0" ] ; then
                KSLOTS=`$SUDO $CRYPTSETUP token export $BDEV --token-id 0 --disable-locks | jq .keyslots | head -n -1 | tail -n -1 | tr -d '"' | tr -d ' '`
                echo "keyslots = '$KSLOTS'" >> $LOG
                if [ `echo $KSLOTS | wc -l` -eq 1 ] && [ "$KSLOTS" = "3" ] ; then
                    R=0
                else 
                    echo "BAD KEYSLOT MAPPING" >>$LOG
                    echo $KEYSLOTS >> $LOG
                    R=1
                fi
                echo $R
            fi
        fi
        if [ -b "$BDEV" ] ; then $SUDO losetup -d $BDEV >> $LOG 2>>$LOG ; fi
        if [ -f "$FDEV" ] ; then rm -rf $FDEV >> $LOG 2>>$LOG ; fi
    )
    if [ "$R" = "0" ] ; then S="P"; SUCCESS=$(($SUCCESS + 1)) ; else S="F"; FAILED=$(($FAILED + 1)) ; fi
else
    SKIPPED=$(($SKIPPED + 1))
    S="S"
fi
printf "%s\t%s\n" "$S" "$TESTNAME"



############################# END TESTS ##############################

cleanup

cat << EOF
Tests:   $TESTS
Skipped: $SKIPPED
Failed:  $FAILED
Success: $SUCCESS
EOF

exit $FAILED
