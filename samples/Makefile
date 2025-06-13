CC = gcc
CFLAGS = -m32 -Wall -Wextra -g -O0 # -O0 to minimize optimizations
LDFLAGS = -static

SRCDIR = .
BINDIR = .

TARGET_EXEC = $(BINDIR)/add
SOURCE_FILE = $(SRCDIR)/add.c

all: $(TARGET_EXEC)

$(TARGET_EXEC): $(SOURCE_FILE)
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) $(SOURCE_FILE) -o $@

clean:
	rm -f $(TARGET_EXEC)

.PHONY: all clean