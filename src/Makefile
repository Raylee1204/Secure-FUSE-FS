COMPILER = gcc
FILESYSTEM_FILES = lsysfs.c
TARGET = lsysfs

# Flags for FUSE and OpenSSL
CFLAGS = -D_FILE_OFFSET_BITS=64 -I/usr/include/fuse3
LDFLAGS = -L/usr/lib/x86_64-linux-gnu -lfuse -lssl -lcrypto

build:
	$(COMPILER) $(FILESYSTEM_FILES) -o $(TARGET) $(CFLAGS) $(LDFLAGS)

clean:
	rm -f $(TARGET)
