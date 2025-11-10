CC = gcc
CFLAGS = -Wall -std=c99 -Iinclude $(shell pkg-config --cflags sqlite3 libsodium)
LDFLAGS = $(shell pkg-config --libs sqlite3 libsodium)

PREFIX = /usr
BINDIR = ${PREFIX}/bin
APP_DIR = /var/lib/unlocky
DB_NAME = unlocky.db
DB_PATH = ${APP_DIR}/${DB_NAME}
GROUP = unlocky
BIN_OWNER = root
BIN_GROUP = ${GROUP}
SHORT_HAND = unlocky

all: build/unlocky

build/unlocky: src/main.c src/db.c 
	$(CC) $(CFLAGS) src/*.c -o build/unlocky $(LDFLAGS)

clean:
	rm -rf build/*

install:
	@echo "=== Installing Unlocky system-wide (requires root) ==="

# Build project
	make clean && make
# Setup SQLite DB
	build/unlocky setup

# Create system group if not yet created
	groupadd -f --system ${GROUP} || { echo "Failed to create group (${GROUP})"; exit 1; }

# Create protected directory
	install -d -m 2770 -o ${BIN_OWNER} -g ${BIN_GROUP} ${APP_DIR} || { echo "Failed to create directory ${APP_DIR}"l exit 1; }

# Install binary 
	install -m 2755 -o ${BIN_OWNER} -g ${BIN_GROUP} build/unlocky ${BINDIR}/${SHORT_HAND}

# short cmd symlink
	@if [ -n "$(SHORT_HAND)" ]; then \
        ln -sfn $(BINDIR)/$(SHORT_HAND) $(BINDIR)/$(SHORT_HAND); \
        echo "Created short command: $(SHORT_HAND)"; \
    fi

# 5. set DB permissions
	chown ${BIN_OWNER}:${BIN_GROUP} ${DB_PATH}
	chmod 0660 ${DB_PATH}

	@echo "=== Installation complete! ==="
	@echo "Try running unlock list"

uninstall:
	@echo "=== unistalling unlocky (requires root) ==="
	rm -r ${BINDIR}/${SHORT_HAND}
	rm -f ${DB_PATH}
	-rmdir ${APP_DIR} 2>/dev/null || true

	@echo "Uninstall complete, group left intakt."