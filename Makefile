CC = gcc
CFLAGS = -Wall -std=c99 -Iinclude

all: build/unlocky

build/unlocky: src/main.c
	$(CC) $(CFLAGS) src/main.c -o build/unlocky

clean:
	rm -rf build/*
