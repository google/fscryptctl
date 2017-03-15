/*
 * fscryptctl.c - Low level tool for managing keys and policies for the
 * fs/crypto kernel interface. Specifically, this tool:
 *     - Computes the descriptor for a provided key
 *
 * Copyright 2017 Google Inc.
 * Author: Joe Richey (joerichey@google.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha512.h"

// Some of the necessary structures and constants are declared in <linux/fs.h>,
// but not all of them (depending on your kernel version). So to simplify
// things, they are just redeclared here.
#define FS_KEY_DESCRIPTOR_SIZE 8
#define FS_KEY_DESCRIPTOR_HEX_SIZE ((2 * FS_KEY_DESCRIPTOR_SIZE) + 1)

#define FS_MAX_KEY_SIZE 64

/* util-linux style usage */
static void __attribute__((__noreturn__)) usage(FILE *out) {
  fputs(
      "\nUsage:\n"
      "  fscryptctl <command> [arguments] [options]\n"
      "\nCommands:\n"
      "  fscryptctl get_descriptor\n"
      "    Read a key from stdin, and print the hex descriptor.\n"
      "\nNotes:\n"
      "  All input keys are 64 bytes long and formatted as binary.\n"
      "  All descriptors are 8 bytes and formatted as hex (16 characters).\n",
      out);

  exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

// Takes an input key descriptor as a byte array and outputs a hex string.
static void key_descriptor_to_hex(const uint8_t bytes[FS_KEY_DESCRIPTOR_SIZE],
                                  char hex[FS_KEY_DESCRIPTOR_HEX_SIZE]) {
  int i;
  for (i = 0; i < FS_KEY_DESCRIPTOR_SIZE; ++i) {
    sprintf(hex + 2 * i, "%02x", bytes[i]);
  }
}

// Reads key data from stdin into the provided data buffer. Return 0 on
// success. Key is wiped if the read fails.
static int read_key(uint8_t key[FS_MAX_KEY_SIZE]) {
  size_t rc = fread(key, 1, FS_MAX_KEY_SIZE, stdin);
  int end = fgetc(stdin);
  // We should read exactly FS_MAX_KEY_SIZE bytes, then hit EOF
  if (rc == FS_MAX_KEY_SIZE && end == EOF && feof(stdin)) {
    return EXIT_SUCCESS;
  }

  secure_wipe(key, FS_MAX_KEY_SIZE);
  fprintf(stderr, "error: input key must be %d bytes\n", FS_MAX_KEY_SIZE);
  return EXIT_FAILURE;
}

// The descriptor is just the first 8 bytes of a double application of SHA512
// formatted as hex (so 16 characters).
static void compute_descriptor(const uint8_t key[FS_MAX_KEY_SIZE],
                               char descriptor[FS_KEY_DESCRIPTOR_HEX_SIZE]) {
  uint8_t digest1[SHA512_DIGEST_LENGTH];
  SHA512(key, FS_MAX_KEY_SIZE, digest1);

  uint8_t digest2[SHA512_DIGEST_LENGTH];
  SHA512(digest1, SHA512_DIGEST_LENGTH, digest2);

  key_descriptor_to_hex(digest2, descriptor);
  secure_wipe(digest1, SHA512_DIGEST_LENGTH);
  secure_wipe(digest2, SHA512_DIGEST_LENGTH);
}

/* Functions for various actions, return 0 on success, non-zero on failure. */

// Get the descriptor for some key data passed via stdin. Provided key data must
// have length FS_MAX_KEY_SIZE. Output will be formatted as hex.
static int cmd_get_descriptor(int argc, char *const argv[]) {
  if (argc != 1) {
    fputs("error: unexpected arguments\n", stderr);
    return EXIT_FAILURE;
  }

  uint8_t key[FS_MAX_KEY_SIZE];
  if (read_key(key)) {
    return EXIT_FAILURE;
  }

  char descriptor[FS_KEY_DESCRIPTOR_HEX_SIZE];
  compute_descriptor(key, descriptor);
  secure_wipe(key, FS_MAX_KEY_SIZE);

  puts(descriptor);
  return EXIT_SUCCESS;
}

int main(int argc, char *const argv[]) {
  static const struct option long_options[] = {{"help", no_argument, NULL, 'h'},
                                               {NULL, 0, NULL, 0}};
  int ch;
  while ((ch = getopt_long(argc, argv, "h", long_options, NULL)) != -1) {
    switch (ch) {
      case 'h':
        usage(stdout);
      default:
        usage(stderr);
    }
  }

  // Remove the provided flags from argv and argc.
  argv += optind;
  argc -= optind;
  if (argc == 0) {
    fputs("error: no command specified\n", stderr);
    usage(stderr);
  }
  const char *command = argv[0];

  if (strcmp(command, "get_descriptor") == 0) {
    return cmd_get_descriptor(argc, argv);
  }

  fprintf(stderr, "error: invalid command: %s\n", command);
  usage(stderr);
}
