# Stealth Hook - User-space programs Makefile
# Cross-compile for Android ARM64

ifndef TARGET_COMPILE
    TARGET_COMPILE = aarch64-linux-gnu-
endif

CC = $(TARGET_COMPILE)gcc
CFLAGS = -O2 -Wall -static -Iinclude

DBI_SRCS = src/dbi_decoder.c src/dbi_recompiler.c

all: xiaojianbang_hook sh_control kpm_loader memread

xiaojianbang_hook: src/xiaojianbang_hook.c $(DBI_SRCS)
	$(CC) $(CFLAGS) -o $@ $^

sh_control: src/sh_control.c
	$(CC) $(CFLAGS) -o $@ $^

# KPM loader: loads/unloads the .kpm via KernelPatch supercall (syscall 45)
kpm_loader: src/kpm_loader.c
	$(CC) $(CFLAGS) -o $@ $^

# memread: read bytes from /proc/<pid>/mem
memread: src/memread.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -f xiaojianbang_hook sh_control kpm_loader memread *.o
