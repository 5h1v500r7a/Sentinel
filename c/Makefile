CC       ?= gcc
CFLAGS   ?= -Wall -Wextra -O2 -fPIC -std=c11
LDLIBS   := -lseccomp
BUILD    := build

.PHONY: all clean

all: $(BUILD)/libsentinel_filter.so $(BUILD)/libsentinel_filter.a

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/seccomp_filter.o: seccomp_filter.c seccomp_filter.h | $(BUILD)
	$(CC) $(CFLAGS) -c seccomp_filter.c -o $@

$(BUILD)/libsentinel_filter.so: $(BUILD)/seccomp_filter.o
	$(CC) -shared -o $@ $< $(LDLIBS)

$(BUILD)/libsentinel_filter.a: $(BUILD)/seccomp_filter.o
	ar rcs $@ $<

clean:
	rm -rf $(BUILD)
