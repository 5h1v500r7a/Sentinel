CC     ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -static
BUILD  := build

.PHONY: all clean

all: $(BUILD)/evil_ptrace $(BUILD)/evil_shell $(BUILD)/evil_socket

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/evil_ptrace: evil_ptrace.c | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD)/evil_shell: evil_shell.c | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD)/evil_socket: evil_socket.c | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(BUILD)
