CC_LINUX   = gcc
CC_WIN     = x86_64-w64-mingw32-gcc
SRC        = tnfs.c
BIN_LINUX  = tnfs
BIN_WIN    = tnfs.exe

CFLAGS_LINUX = -O2 -Wall -Wextra -o $(BIN_LINUX) $(SRC) \
               $(shell pkg-config --cflags --libs gtk+-3.0) -lpthread

CFLAGS_WIN   = -O2 -Wall -Wextra -o $(BIN_WIN) $(SRC) \
               -lws2_32 -ladvapi32 -mwindows

.PHONY: all linux windows clean

all: linux

linux:
	$(CC_LINUX) $(CFLAGS_LINUX)

windows:
	$(CC_WIN) $(CFLAGS_WIN)

clean:
	rm -f $(BIN_LINUX) $(BIN_WIN)
