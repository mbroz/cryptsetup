# LD_LIBRARY_PATH=../../lib/.libs
TARGETS=crypt_log_usage crypt_luks_usage
CFLAGS=-O0 -g -Wall -D_GNU_SOURCE -I../../lib
LDLIBS=-lcryptsetup -L../../lib/.libs 
CC=gcc

all: $(TARGETS)

crypt_log_usage: crypt_log_usage.o
	$(CC) -o $@ $^ $(LDLIBS)

crypt_luks_usage: crypt_luks_usage.o
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	rm -f *.o *~ core $(TARGETS)

.PHONY: clean
