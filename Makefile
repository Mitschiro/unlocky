CC = gcc
CFLAGS = -Wall -std=c99 -Iinclude $(shell pkg-config --cflags sqlite3 libsodium)
LDFLAGS = $(shell pkg-config --libs sqlite3 libsodium)

all: build/unlocky

build/unlocky: src/main.c src/db.c 
	$(CC) $(CFLAGS) src/*.c -o build/unlocky $(LDFLAGS)

clean:
	rm -rf build/*
