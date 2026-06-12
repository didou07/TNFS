CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -Iinclude
SRCS    = src/crypto.c src/util.c src/tvcas.c src/config.c \
          src/ecm.c src/newcamd.c src/worker.c src/log.c src/main.c
TARGET  = tnfs

ifeq ($(OS),Windows_NT)
    CFLAGS  += -DWIN32 -mwindows
    LDFLAGS  = -lws2_32 -ladvapi32
    TARGET  := $(TARGET).exe
else
    CFLAGS  += $(shell pkg-config --cflags gtk+-3.0)
    LDFLAGS  = $(shell pkg-config --libs gtk+-3.0) -lpthread
endif

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET) tnfs.exe
