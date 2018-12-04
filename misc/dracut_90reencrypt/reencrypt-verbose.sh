#!/bin/sh

# Route stdout to stderr in initrd. Otherwise output is invisible
# unless we run in debug mode.
# shellcheck disable=SC2068
/sbin/cryptsetup-reencrypt $@ 1>&2
