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

NAME = fscryptctl
CFLAGS += -O2 -Wall

INSTALL = install
DESTDIR = /usr/local/bin

OBJECTS = $(NAME).o sha512.o

.PHONY: default all clean format $(NAME)

default: $(NAME)
all: format $(NAME) test

$(NAME): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

format:
	@find . -name '*.c' -or -name '*.h' | xargs clang-format -style=Google -i

test: $(NAME)
	@python -m pytest test.py -s -q

install: $(NAME)
	$(INSTALL) -d $(DEST_DIR)
	$(INSTALL) $(NAME) $(DEST_DIR)

clean:
	rm -f $(OBJECTS)
	rm -rf $(NAME)
	rm -rf .cache
	rm -rf __pycache__
