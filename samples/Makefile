CC = gcc
CFLAGS = -m32 -Wall -Wextra -g -fno-pie -O0 # -O0 to minimize optimizations
LDFLAGS = -static -no-pie

SRCDIR = .
BINDIR = .

TARGET_EXEC = $(BINDIR)/add
SOURCE_FILE = $(SRCDIR)/add.c

all: $(TARGET_EXEC)

$(TARGET_EXEC): $(SOURCE_FILE)
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $(SOURCE_FILE) -o $@ $(LDFLAGS)

clean:
	rm -f $(TARGET_EXEC)

.PHONY: all clean