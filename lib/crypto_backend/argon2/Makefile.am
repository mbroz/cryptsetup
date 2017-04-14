moduledir = $(libdir)/cryptsetup

noinst_LTLIBRARIES = libargon2.la

libargon2_la_CFLAGS = $(AM_CFLAGS) -std=c89 -pthread -O3 -Wall

libargon2_la_SOURCES = \
	blake2/blake2b.c blake2/blake2.h blake2/blake2-impl.h blake2/blamka-round-opt.h blake2/blamka-round-ref.h \
	argon2.c argon2.h core.c core.h encoding.c encoding.h ref.c thread.c thread.h

AM_CPPFLAGS = -Iblake2

EXTRA_DIST = LICENSE
