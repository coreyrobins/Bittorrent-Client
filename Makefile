
INCLUDE_FILES=utils.h sha1.h bencode.h
CFLAGS=-g -Wall -O0 -Wwrite-strings -Wshadow -fstack-protector-all -lm 
all: bittorrent
bittorrent: bittorrent.o bencode.o utils.o sha1.o bitset.o
	$(CC) $(CFLAGS) $^ -o $@
pa1: pa2-listips.o bencode.o utils.o sha1.o
	$(CC) $(CFLAGS) $^ -o $@
clean: 
	rm -f *.o pa1 pa4
pa1e: bittorrent.o bencode.o utils.o sha1.o
	$(CC) $(CFLAGS) $^ -o $@ -lefence
pa1m: bittorrent.o bencode.o utils.o sha1.o
	$(CC) $(CFLAGS) $^ -o $@ -lmallocdebug
depend:
	makdepend *.c
