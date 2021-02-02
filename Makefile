# Makefile for fscryptctl
#
# Copyright 2017, 2020 Google LLC
#
# Authors: Joe Richey (joerichey@google.com),
#          Eric Biggers (ebiggers@google.com)
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

##############################################################################

# Makefile options.  These can be overridden on the command line,
# e.g. make PREFIX=/usr or PREFIX=/usr make.

# Installation path prefix
PREFIX ?= /usr/local

# Directory where the binary gets installed
BINDIR ?= $(PREFIX)/bin

# C compiler flags
CFLAGS ?= -O2 -Wall

# C preprocessor flags
CPPFLAGS ?=

# Linker flags
LDFLAGS ?=

# Pass the version to the command line program (pulled from tags).
VERSION ?= $(shell git describe --tags 2>/dev/null)
override CPPFLAGS += $(if $(VERSION),-DVERSION="\"$(VERSION)\"")

##############################################################################

# Build the binary

SRC := $(wildcard *.c)
OBJ := $(SRC:.c=.o)
HDRS := $(wildcard *.h)

fscryptctl: $(OBJ)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $+

$(OBJ): %.o: %.c $(HDRS)
	$(CC) -o $@ -c $(CPPFLAGS) $(CFLAGS) $<

##############################################################################

# Don't format fscrypt_uapi.h, so that it stays identical to the kernel version.
FILES_TO_FORMAT := $(filter-out fscrypt_uapi.h, $(SRC) $(HDRS))

.PHONY: format format-check
format:
	clang-format -i -style=Google $(FILES_TO_FORMAT)

format-check:
	@clang-format -i -style=Google -output-replacements-xml \
		$(FILES_TO_FORMAT) \
	| grep "<replacement " \
	| ./input_fail.py "Incorrectly formatted C files. Run \"make format\"."

##############################################################################

# Testing targets

# The 'test' target requires that $(TEST_DIR) point to a directory on a
# filesystem that supports encryption.
#
# 'test-setup' sets up the default TEST_DIR to point to a directory on a
# temporary ext4 filesystem on a loopback device.  'test-teardown' cleans up
# afterwards.  Note that both of these use 'sudo'.
#
# 'test-all' runs 'test-setup', 'test', and 'test-teardown'.

TEST_IMAGE ?= /tmp/fscryptctl-test-image
TEST_DIR ?= /tmp/fscryptctl-test-dir

.PHONY: test test-setup test-teardown test-all

test: fscryptctl
	@if [ ! -e "$(TEST_DIR)" ]; then \
		echo 1>&2 "Directory $(TEST_DIR) does not exist, run 'make test-setup'"; \
		exit 1; \
	fi
	TEST_DIR="$(TEST_DIR)" PATH="$$PWD:$$PATH" \
		 ENABLE_VALGRIND="$(ENABLE_VALGRIND)" \
		 python3 -m pytest test.py -s -q

# Depend on test-teardown so that anything already present is cleaned up first.
test-setup:test-teardown
	dd if=/dev/zero of="$(TEST_IMAGE)" bs=1M count=32
	mkfs.ext4 -b 4096 -O encrypt -F "$(TEST_IMAGE)"
	mkdir -p "$(TEST_DIR)"
	sudo mount -o rw,loop "$(TEST_IMAGE)" "$(TEST_DIR)"
	sudo sh -c 'chown $$SUDO_UID:$$SUDO_GID "$(TEST_DIR)"'
	@echo
	@echo "$(TEST_DIR) is now set up."

test-teardown:
	if mountpoint --quiet "$(TEST_DIR)"; then \
		sudo umount "$(TEST_DIR)"; \
	fi
	rm -rf "$(TEST_DIR)"
	rm -f "$(TEST_IMAGE)"

test-all:
	$(MAKE) test-setup
	$(MAKE) test
	$(MAKE) test-teardown

##############################################################################

# Installation, uninstallation, and cleanup targets

.PHONY: install uninstall clean
install: fscryptctl
	install -d $(DESTDIR)$(BINDIR)
	install -m755 $< $(DESTDIR)$(BINDIR)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/fscryptctl

clean:
	rm -f fscryptctl *.o *.pyc
	rm -rf __pycache__
	rm -rf .pytest_cache
