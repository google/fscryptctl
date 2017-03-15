/*
 * fscryptctl.c - Low level tool for managing keys and policies for the
 * fs/crypto kernel interface. Specifically, this tool:
 *     - Computes the descriptor for a provided key
 *     - Inserts a provided key into the keyring
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
#include <sys/syscall.h>
#include <unistd.h>

#include "sha512.h"

// Some of the necessary structures, constants, and functions are declared in
// <linux/fs.h> or <keyutils.h> but are either incomplete (depending on your
// kernel version) or require an external library. So to simplify things, they
// are just redeclared here.
/* Begin <linux/fs.h> */
#define FS_MAX_KEY_SIZE 64

struct fscrypt_key {
  uint32_t mode;
  uint8_t raw[FS_MAX_KEY_SIZE];
  uint32_t size;
} __attribute__((packed));

#define FS_KEY_DESCRIPTOR_SIZE 8
#define FS_KEY_DESCRIPTOR_HEX_SIZE ((2 * FS_KEY_DESCRIPTOR_SIZE) + 1)

// Service prefixes for encryption keys
#define FS_KEY_DESC_PREFIX "fscrypt:"
#define EXT4_KEY_DESC_PREFIX "ext4:"  // For ext4 before 4.8 kernel
#define F2FS_KEY_DESC_PREFIX "f2fs:"  // For f2fs before 4.6 kernel
#define MAX_KEY_DESC_PREFIX_SIZE 8
/* End <linux/fs.h> */

/* Begin <keyutils.h> */
typedef int32_t key_serial_t;
#define KEYCTL_GET_KEYRING_ID 0     /* ask for a keyring's ID */
#define KEY_SPEC_SESSION_KEYRING -3 /* current session keyring */

key_serial_t add_key(const char *type, const char *description,
                     const void *payload, size_t plen, key_serial_t ringid) {
  return syscall(__NR_add_key, type, description, payload, plen, ringid);
}

key_serial_t keyctl_get_keyring_ID(key_serial_t id, int create) {
  return syscall(__NR_keyctl, KEYCTL_GET_KEYRING_ID, id, create);
}
/* End <keyutils.h> */

// Which prefix will be used in this program, changed via command line flag.
const char *service_prefix = FS_KEY_DESC_PREFIX;

/* util-linux style usage */
static void __attribute__((__noreturn__)) usage(FILE *out) {
  fputs(
      "\nUsage:\n"
      "  fscryptctl <command> [arguments] [options]\n"
      "\nCommands:\n"
      "  fscryptctl get_descriptor\n"
      "    Read a key from stdin, and print the hex descriptor of the key.\n"
      "  fscryptctl insert_key\n"
      "    Read a key from stdin, insert the key into the current session\n"
      "    keyring (or the user session keyring if a session keyring does not\n"
      "    exist), and print the descriptor of the key.\n"
      "\nOptions:\n"
      " --ext4       for using insert_key with ext4 before kernel v4.8\n"
      " --f2fs       for using insert_key with F2FS before kernel v4.6\n"
      " -h, --help   print this help screen\n"
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

// Reads key data from stdin into the provided data buffer. Return 0 on success.
static int read_key(uint8_t key[FS_MAX_KEY_SIZE]) {
  size_t rc = fread(key, 1, FS_MAX_KEY_SIZE, stdin);
  int end = fgetc(stdin);
  // We should read exactly FS_MAX_KEY_SIZE bytes, then hit EOF
  if (rc == FS_MAX_KEY_SIZE && end == EOF && feof(stdin)) {
    return EXIT_SUCCESS;
  }

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

// Inserts the key into the current session keyring with type logon and the
// service specified by service_prefix.
static int insert_logon_key(const uint8_t key_data[FS_MAX_KEY_SIZE],
                            const char descriptor[FS_KEY_DESCRIPTOR_HEX_SIZE]) {
  // We cannot add directly to KEY_SPEC_SESSION_KEYRING, as that will make a new
  // session keyring if one does not exist, rather than adding it to the user
  // session keyring.
  int keyring_id = keyctl_get_keyring_ID(KEY_SPEC_SESSION_KEYRING, 0);
  if (keyring_id < 0) {
    return EXIT_FAILURE;
  }

  char description[MAX_KEY_DESC_PREFIX_SIZE + FS_KEY_DESCRIPTOR_HEX_SIZE];
  sprintf(description, "%s%s", service_prefix, descriptor);

  struct fscrypt_key key = {.mode = 0, .size = FS_MAX_KEY_SIZE};
  memcpy(key.raw, key_data, FS_MAX_KEY_SIZE);

  int ret = add_key("logon", description, &key, sizeof(key), keyring_id) < 0
                ? EXIT_FAILURE
                : EXIT_SUCCESS;

  secure_wipe(key.raw, FS_MAX_KEY_SIZE);
  return ret;
}

/* Functions for various actions, return 0 on success, non-zero on failure. */

// Get the descriptor for some key data passed via stdin. Provided key data must
// have length FS_MAX_KEY_SIZE. Output will be formatted as hex.
static int cmd_get_descriptor(int argc, char *const argv[]) {
  if (argc != 1) {
    fputs("error: unexpected arguments\n", stderr);
    return EXIT_FAILURE;
  }

  int ret = EXIT_SUCCESS;
  uint8_t key[FS_MAX_KEY_SIZE];
  if (read_key(key)) {
    ret = EXIT_FAILURE;
    goto cleanup;
  }

  char descriptor[FS_KEY_DESCRIPTOR_HEX_SIZE];
  compute_descriptor(key, descriptor);
  puts(descriptor);

cleanup:
  secure_wipe(key, FS_MAX_KEY_SIZE);
  return ret;
}

// Insert a key read from stdin into the current session keyring. This has the
// effect of unlocking files encrypted with that key.
static int cmd_insert_key(int argc, char *const argv[]) {
  if (argc != 1) {
    fputs("error: unexpected arguments\n", stderr);
    return EXIT_FAILURE;
  }

  int ret = EXIT_SUCCESS;
  uint8_t key[FS_MAX_KEY_SIZE];
  if (read_key(key)) {
    ret = EXIT_FAILURE;
    goto cleanup;
  }

  char descriptor[FS_KEY_DESCRIPTOR_HEX_SIZE];
  compute_descriptor(key, descriptor);
  if (insert_logon_key(key, descriptor)) {
    fprintf(stderr, "error: inserting key: %s\n", strerror(errno));
    ret = EXIT_FAILURE;
    goto cleanup;
  }
  puts(descriptor);

cleanup:
  secure_wipe(key, FS_MAX_KEY_SIZE);
  return ret;
}

int main(int argc, char *const argv[]) {
  static const struct option long_options[] = {{"ext4", no_argument, NULL, 'e'},
                                               {"f2fs", no_argument, NULL, 'f'},
                                               {"help", no_argument, NULL, 'h'},
                                               {NULL, 0, NULL, 0}};
  int ch;
  while ((ch = getopt_long(argc, argv, "h", long_options, NULL)) != -1) {
    switch (ch) {
      case 'e':
        service_prefix = EXT4_KEY_DESC_PREFIX;
        break;
      case 'f':
        service_prefix = F2FS_KEY_DESC_PREFIX;
        break;
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
  } else if (strcmp(command, "insert_key") == 0) {
    return cmd_insert_key(argc, argv);
  }

  fprintf(stderr, "error: invalid command: %s\n", command);
  usage(stderr);
}
