#!/bin/sh

# Route stdout to stderr in initrd. Otherwise output is invisible
# unless we run in debug mode.
/sbin/cryptsetup-reencrypt $@ 1>&2
