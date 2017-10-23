# Makefile for fscryptctl
#
# Copyright 2017 Google Inc.
# Author: Joe Richey (joerichey@google.com)
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

# Update on each new release!!
RELEASE_VERSION = 0.1.0

NAME = fscryptctl

INSTALL ?= install
DESTDIR ?= /usr/local/bin

C_FILES = $(shell find . -type f -name "*.h" -o -name "*.c")

# IMAGE will be the path to our test ext4 image file.
IMAGE ?= $(NAME)_image

# MOUNT will be the path to the filesystem where our tests are run.
#
# Running "make test-setup MOUNT=/foo/bar" creates a test filesystem at that
#	location. Be sure to also run "make test-teardown MOUNT=/foo/bar".
# Running "make all MOUNT=/foo/bar" (or "make go") will run all tests on that
# 	filesystem. By default, it is the one created with "make test-setup".
MOUNT ?= /mnt/$(NAME)_mount
export TEST_FILESYSTEM_ROOT = $(MOUNT)

# The flags code below lets the caller of the makefile change the build flags
# for fscryptctl in a familiar manner.
#	CFLAGS
#		Change the flags passed to the C compiler. Default = "-O2 -Wall"
#		For example:
#			make "CFLAGS = -O3 -Werror"
#		builds the C code with high optimizations, and C warnings fail.
#	LDFLAGS
#		Change the flags passed to the C linker. Empty by default.
#		For example (on my system with additional dev packages):
#			make "LDFLAGS = -static"
#		will build a static fscrypt binary.

# Set the C flags so we don't need to set C flags in each CGO file.
CFLAGS ?= -O2 -Wall

# Pass the version to the command line program (pulled from tags).
TAG_VERSION = $(shell git describe --tags 2>/dev/null)
VERSION = $(if $(TAG_VERSION),$(TAG_VERSION),$(RELEASE_VERSION))

.PHONY: default
default: $(NAME)

sha512.o: sha512.h sha512.c
	$(CC) $(CPPFLAGS) $(CFLAGS) sha512.c -c -o $@

$(NAME).o: $(NAME).c sha512.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -DVERSION="\"$(VERSION)\"" $(NAME).c -c -o $@

$(NAME): $(NAME).o sha512.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

# Testing fscryptctl (need root permissions)
.PHONY: root test
root:
ifneq ($(shell id -u),0)
	$(error You must be root to execute this command)
endif

test: $(NAME) root
ifeq ("$(wildcard $(MOUNT))","")
	$(error mountpoint $(MOUNT) does not exist, run "make test-setup")
endif
	python -m pytest test.py -s -q

# Format all the Go and C code
.PHONY: format format-check
format:
	clang-format -i -style=Google $(C_FILES)

format-check:
	@clang-format -i -style=Google -output-replacements-xml $(C_FILES) \
	| grep "<replacement " \
	| ./input_fail.py "Incorrectly formatted C files. Run \"make format\"."

# Installation, uninstallation, and cleanup code
.PHONY: install uninstall clean
install: $(NAME)
	$(INSTALL) -d $(DESTDIR)
	$(INSTALL) $(NAME) $(DESTDIR)

uninstall:
	rm -f $(DESTDIR)/$(NAME)

clean:
	rm -f $(NAME) *.o *.pyc $(IMAGE)
	rm -rf .cache
	rm -rf __pycache__

##### Setup/Teardown for integration tests (need root permissions) #####
.PHONY: test-setup test-teardown
test-setup: root
	dd if=/dev/zero of=$(IMAGE) bs=1M count=20
	mkfs.ext4 -b 4096 -O encrypt $(IMAGE) -F
	mkdir -p $(MOUNT)
	mount -o rw,loop,user $(IMAGE) $(MOUNT)
	chmod +777 $(MOUNT)

test-teardown: root
	umount $(MOUNT)
	rmdir $(MOUNT)
	rm -f $(IMAGE)

##### Travis CI Commands
.PHONY: travis-install travis-script
travis-install: test-setup

travis-script: format-check default test
