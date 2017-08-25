#!/bin/sh
SUP="--suppressions=./cryptsetup-valg-supps"
CHILD="--trace-children=yes --child-silent-after-fork=yes"
MALLOC="--malloc-fill=aa"
FREE="--free-fill=21"
STACK="--max-stackframe=2000000"
EXTRAS="--read-var-info=yes --show-reachable=yes"
LOGFILE="--log-file=./valglog.$(date +%s)_${INFOSTRING}"
LEAKCHECK="--leak-check=full --track-origins=yes"

exec valgrind  $SUP $GETSUP $CHILD $MALLOC $FREE $STACK $EXTRAS $LOGFILE  $LEAKCHECK "$@"
