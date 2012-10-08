TARGETS=chk_luks_keyslots
CFLAGS=-O0 -g -Wall -D_GNU_SOURCE
LDLIBS=-lcryptsetup -lm
CC=gcc

all: $(TARGETS)

chk_luks_keyslots: chk_luks_keyslots.o
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	rm -f *.o *~ core $(TARGETS)

.PHONY: clean
