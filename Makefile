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

##############################################################################

# Update on each new release!!
RELEASE_VERSION = 0.1.0

# Pass the version to the command line program (pulled from tags).
TAG_VERSION = $(shell git describe --tags 2>/dev/null)
VERSION = $(if $(TAG_VERSION),$(TAG_VERSION),$(RELEASE_VERSION))

##############################################################################

# Build the binary

SRC := $(wildcard *.c)
OBJ := $(SRC:.c=.o)
HDRS := $(wildcard *.h)

fscryptctl: $(OBJ)
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $+

$(OBJ): %.o: %.c $(HDRS)
	$(CC) -o $@ -c $(CPPFLAGS) $(CFLAGS) -DVERSION="\"$(VERSION)\"" $<

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

# IMAGE will be the path to our test ext4 image file.
IMAGE ?= fscryptctl_image

# MOUNT will be the path to the filesystem where our tests are run.
#
# Running "make test-setup MOUNT=/foo/bar" creates a test filesystem at that
#	location. Be sure to also run "make test-teardown MOUNT=/foo/bar".
# Running "make test MOUNT=/foo/bar" will run all tests on that filesystem. By
#       default, it is the one created with "make test-setup".
MOUNT ?= /mnt/fscryptctl_mount
export TEST_FILESYSTEM_ROOT = $(MOUNT)

.PHONY: root test
root:
ifneq ($(shell id -u),0)
	$(error You must be root to execute this command)
endif

test: fscryptctl root
ifeq ("$(wildcard $(MOUNT))","")
	$(error mountpoint $(MOUNT) does not exist, run "make test-setup")
endif
	python -m pytest test.py -s -q

.PHONY: test-setup test-teardown
test-setup: root
	dd if=/dev/zero of=$(IMAGE) bs=1M count=20
	mkfs.ext4 -b 4096 -O encrypt -F $(IMAGE)
	mkdir -p $(MOUNT)
	mount -o rw,loop,user $(IMAGE) $(MOUNT)
	chmod +777 $(MOUNT)

test-teardown: root
	umount $(MOUNT)
	rmdir $(MOUNT)
	rm -f $(IMAGE)

.PHONY: travis-install travis-script
travis-install: test-setup

travis-script: format-check fscryptctl test

##############################################################################

# Installation, uninstallation, and cleanup targets

.PHONY: install uninstall clean
install: fscryptctl
	install -d $(DESTDIR)$(BINDIR)
	install -m755 $< $(DESTDIR)$(BINDIR)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/fscryptctl

clean:
	rm -f fscryptctl *.o *.pyc $(IMAGE)
	rm -rf __pycache__
	rm -rf .cache
