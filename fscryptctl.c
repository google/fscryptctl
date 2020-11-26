/*
 * fscryptctl.c - Low level tool for managing keys and policies for the
 * fs/crypto kernel interface. Specifically, this tool:
 *     - Computes the descriptor for a provided key
 *     - Inserts a provided key into the keyring
 *     - Queries the key descriptor for an encrypted directory
 *     - Applies an encryption policy to an empty directory
 *
 * Copyright 2017, 2020 Google LLC
 *
 * Authors: Joe Richey (joerichey@google.com),
 *          Eric Biggers (ebiggers@google.com)
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
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "fscrypt_uapi.h"
#include "keyutils.h"
#include "sha512.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

#define FSCRYPT_KEY_DESCRIPTOR_HEX_SIZE ((2 * FSCRYPT_KEY_DESCRIPTOR_SIZE) + 1)
#define FSCRYPT_KEY_IDENTIFIER_HEX_SIZE ((2 * FSCRYPT_KEY_IDENTIFIER_SIZE) + 1)

// Service prefixes for encryption keys
#define EXT4_KEY_DESC_PREFIX "ext4:"  // For ext4 before 4.8 kernel
#define F2FS_KEY_DESC_PREFIX "f2fs:"  // For f2fs before 4.6 kernel
#define MAX_KEY_DESC_PREFIX_SIZE 8

// Human-readable strings for encryption modes, indexed by the encryption mode
static const char *const mode_strings[] = {
    [FSCRYPT_MODE_AES_256_XTS] = "AES-256-XTS",
    [FSCRYPT_MODE_AES_256_CTS] = "AES-256-CTS",
    [FSCRYPT_MODE_AES_128_CBC] = "AES-128-CBC",
    [FSCRYPT_MODE_AES_128_CTS] = "AES-128-CTS",
    [FSCRYPT_MODE_ADIANTUM] = "Adiantum",
};

// Valid amounts of filename padding, indexed by the padding flag
static const int padding_values[] = {4, 8, 16, 32};

enum {
  OPT_ALL_USERS,
  OPT_CONTENTS,
  OPT_DIRECT_KEY,
  OPT_FILENAMES,
  OPT_IV_INO_LBLK_32,
  OPT_IV_INO_LBLK_64,
  OPT_PADDING,
};

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
      "  fscryptctl add_key <mountpoint>\n"
      "    Read a key from stdin, add it to the specified mounted filesystem,\n"
      "    and print its identifier.\n"
      "  fscryptctl remove_key <key identifier> <mountpoint>\n"
      "    Remove the key with the specified identifier from the specified\n"
      "    mounted filesystem.\n"
      "  fscryptctl key_status <key identifier> <mountpoint>\n"
      "    Get the status of the key with the specified identifier on the\n"
      "    specified mounted filesystem.\n"
      "  fscryptctl get_policy <file or directory>\n"
      "    Print out the encryption policy for the specified path.\n"
      "  fscryptctl set_policy <key identifier or descriptor> <directory>\n"
      "    Set up an encryption policy on the specified directory with the\n"
      "    specified key identifier or descriptor.\n"
      "\nOptions:\n"
      "    -h, --help\n"
      "        print this help screen\n"
      "    -v, --version\n"
      "        print the version of fscrypt\n"
      "    insert_key\n"
      "        --ext4\n"
      "            for use with an ext4 filesystem before kernel v4.8\n"
      "        --f2fs\n"
      "            for use with an F2FS filesystem before kernel v4.6\n"
      "    remove_key\n"
      "        --all-users\n"
      "            force-remove all users' claims to the key (requires root)\n"
      "    set_policy\n"
      "        --contents=<mode>\n"
      "            contents encryption mode (default: AES-256-XTS)\n"
      "        --filenames=<mode>\n"
      "            filenames encryption mode (default: AES-256-CTS)\n"
      "        --padding=<bytes>\n"
      "            bytes of zero padding for filenames (default: 32)\n"
      "        --direct-key\n"
      "            optimize for Adiantum encryption\n"
      "        --iv-ino-lblk-64\n"
      "            optimize for UFS inline crypto hardware\n"
      "        --iv-ino-lblk-32\n"
      "            optimize for eMMC inline crypto hardware (not recommended)\n"
      "\nNotes:\n"
      "  All input keys are 64 bytes long and formatted as binary.\n"
      "  All descriptors are 8 bytes and formatted as hex (16 characters).\n",
      out);

  exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

// Preprocesses argc and argv for a command that takes no options.  (It may take
// positional parameters.)  This makes the command handle all options as unknown
// options and handle "--" as "end of options", rather than treating them as
// positional parameters.  This way, we can add options in the future if needed.
static void handle_no_options(int *argc, char *const *argv[]) {
  static const struct option no_options[] = {{NULL, 0, NULL, 0}};
  int ch = getopt_long(*argc, *argv, "", no_options, NULL);
  if (ch != -1) {
    usage(stderr);
  }
  *argc -= optind;
  *argv += optind;
}

// Describes common error codes for the fscrypt ioctls.
static const char *describe_fscrypt_error(int errno_val) {
  switch (errno_val) {
    case ENOTTY:
      return "your kernel is too old to support filesystem encryption, or the "
             "filesystem you are using does not support encryption";
    case EOPNOTSUPP:
      return "filesystem encryption has been disabled in the kernel config, or "
             "you need to enable encryption on your filesystem (see the README "
             "for more detailed instructions).";
    default:
      return strerror(errno_val);
  }
}

// Describes the error codes for the FS_IOC_GET_ENCRYPTION_POLICY{,_EX} ioctls.
static const char *describe_get_policy_error(int errno_val) {
  switch (errno_val) {
    case ENODATA:
      return "file or directory not encrypted";
    case EINVAL:
    case EOVERFLOW:
      return "file or directory uses an unrecognized encryption policy version";
    default:
      return describe_fscrypt_error(errno_val);
  }
}

// Describes the error codes for the FS_IOC_SET_ENCRYPTION_POLICY ioctl.
static const char *describe_set_policy_error(int errno_val) {
  switch (errno_val) {
    case EEXIST:
      return "file or directory already encrypted";
    case EINVAL:
      return "invalid encryption options provided";
    default:
      return describe_fscrypt_error(errno_val);
  }
}

// Describes the error codes for the FS_IOC_ADD_ENCRYPTION_KEY,
// FS_IOC_REMOVE_ENCRYPTION_KEY{,_ALL_USERS}, and
// FS_IOC_GET_ENCRYPTION_KEY_STATUS ioctls.
static const char *describe_fscrypt_v2_error(int errno_val) {
  if (errno_val == ENOTTY) {
    struct utsname u;
    int major, minor;

    if (uname(&u) == 0 && sscanf(u.release, "%d.%d", &major, &minor) == 2 &&
        (major < 5 || (major == 5 && minor < 4))) {
      return "ioctl not implemented.  Your kernel may be too old to support "
             "all the fscrypt ioctls.  Please upgrade to Linux 5.4 or later.";
    }
  }
  return describe_fscrypt_error(errno_val);
}

// Converts str to an encryption mode.  Returns false if the string does not
// correspond to an encryption mode.
static bool string_to_mode(const char *str, uint8_t *mode_ret) {
  for (size_t i = 0; i < ARRAY_SIZE(mode_strings); i++) {
    if (mode_strings[i] != NULL && strcmp(str, mode_strings[i]) == 0) {
      *mode_ret = i;
      return true;
    }
  }
  return false;
}

// Converts the encryption mode to a human-readable string.  Returns NULL if the
// mode is not a valid encryption mode.
static const char *mode_to_string(uint8_t mode) {
  if (mode >= ARRAY_SIZE(mode_strings)) {
    return NULL;
  }
  return mode_strings[mode];
}

// Converts an amount of padding (as a string) into the appropriate padding
// flag. Returns -1 if the flag is invalid.
static int string_to_padding_flag(const char *str) {
  int padding = atoi(str);
  for (size_t i = 0; i < ARRAY_SIZE(padding_values); i++) {
    if (padding == padding_values[i]) {
      return i;
    }
  }
  return -1;
}

// Converts an array of bytes to hex.  The output string will be
// (2*num_bytes)+1 characters long including the null terminator.
static void bytes_to_hex(const uint8_t *bytes, size_t num_bytes, char *hex) {
  for (size_t i = 0; i < num_bytes; i++) {
    sprintf(&hex[2 * i], "%02x", bytes[i]);
  }
}

// Converts a hex string to bytes, where the output length is known.
static bool hex_to_bytes(const char *hex, uint8_t *bytes, size_t num_bytes) {
  if (strlen(hex) != 2 * num_bytes) {
    return false;
  }
  for (size_t i = 0; i < num_bytes; i++) {
    // We must read two hex characters of input into one byte of buffer.
    int chars_read = 0;
    int ret = sscanf(&hex[2 * i], "%2hhx%n", &bytes[i], &chars_read);
    if (ret != 1 || chars_read != 2) {
      return false;
    }
  }
  return true;
}

// Builds a 'struct fscrypt_key_specifier' for passing to the kernel, given a
// key identifier hex string.
static bool build_key_specifier(const char *identifier_hex,
                                struct fscrypt_key_specifier *key_spec) {
  memset(key_spec, 0, sizeof(*key_spec));
  if (!hex_to_bytes(identifier_hex, key_spec->u.identifier,
                    FSCRYPT_KEY_IDENTIFIER_SIZE)) {
    fprintf(stderr, "error: invalid key identifier: %s\n", identifier_hex);
    return false;
  }
  key_spec->type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
  return true;
}

// Reads key data from stdin into the provided data buffer. Return 0 on success.
static int read_key(uint8_t key[FSCRYPT_MAX_KEY_SIZE]) {
  size_t rc = fread(key, 1, FSCRYPT_MAX_KEY_SIZE, stdin);
  int end = fgetc(stdin);
  // We should read exactly FSCRYPT_MAX_KEY_SIZE bytes, then hit EOF
  if (rc == FSCRYPT_MAX_KEY_SIZE && end == EOF && feof(stdin)) {
    return 0;
  }

  fprintf(stderr, "error: input key must be %d bytes\n", FSCRYPT_MAX_KEY_SIZE);
  return -1;
}

// The descriptor is just the first 8 bytes of a double application of SHA512
// formatted as hex (so 16 characters).
static void compute_descriptor(
    const uint8_t key[FSCRYPT_MAX_KEY_SIZE],
    char descriptor[FSCRYPT_KEY_DESCRIPTOR_HEX_SIZE]) {
  uint8_t digest1[SHA512_DIGEST_LENGTH];
  SHA512(key, FSCRYPT_MAX_KEY_SIZE, digest1);

  uint8_t digest2[SHA512_DIGEST_LENGTH];
  SHA512(digest1, SHA512_DIGEST_LENGTH, digest2);

  bytes_to_hex(digest2, FSCRYPT_KEY_DESCRIPTOR_SIZE, descriptor);
  secure_wipe(digest1, SHA512_DIGEST_LENGTH);
  secure_wipe(digest2, SHA512_DIGEST_LENGTH);
}

// Inserts the key into the current session keyring with type logon and the
// service specified by service_prefix.
static int insert_logon_key(
    const uint8_t key_data[FSCRYPT_MAX_KEY_SIZE],
    const char descriptor[FSCRYPT_KEY_DESCRIPTOR_HEX_SIZE],
    const char *service_prefix) {
  // We cannot add directly to KEY_SPEC_SESSION_KEYRING, as that will make a new
  // session keyring if one does not exist, rather than adding it to the user
  // session keyring.
  int keyring_id = keyctl_get_keyring_ID(KEY_SPEC_SESSION_KEYRING, 0);
  if (keyring_id < 0) {
    return -1;
  }

  char description[MAX_KEY_DESC_PREFIX_SIZE + FSCRYPT_KEY_DESCRIPTOR_HEX_SIZE];
  sprintf(description, "%s%s", service_prefix, descriptor);

  struct fscrypt_key key = {.mode = 0, .size = FSCRYPT_MAX_KEY_SIZE};
  memcpy(key.raw, key_data, FSCRYPT_MAX_KEY_SIZE);

  int ret =
      add_key("logon", description, &key, sizeof(key), keyring_id) < 0 ? -1 : 0;

  secure_wipe(key.raw, FSCRYPT_MAX_KEY_SIZE);
  return ret;
}

static bool get_policy(const char *path,
                       struct fscrypt_get_policy_ex_arg *arg) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr, "error: opening %s: %s\n", path, strerror(errno));
    return false;
  }

  arg->policy_size = sizeof(arg->policy);
  int ret = ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY_EX, arg);
  if (ret != 0 && errno == ENOTTY) {
    // The kernel may be too old to support FS_IOC_GET_ENCRYPTION_POLICY_EX.
    // Try FS_IOC_GET_ENCRYPTION_POLICY instead.
    ret = ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY, arg->policy.v1);
  }
  close(fd);

  if (ret != 0) {
    fprintf(stderr, "error: getting policy for %s: %s\n", path,
            describe_get_policy_error(errno));
    return false;
  }
  return true;
}

#undef fscrypt_policy
union fscrypt_policy {
  uint8_t version;
  struct fscrypt_policy_v1 v1;
  struct fscrypt_policy_v2 v2;
};

static bool set_policy(const char *path, const union fscrypt_policy *policy) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr, "error: opening %s: %s\n", path, strerror(errno));
    return false;
  }

  int ret = ioctl(fd, FS_IOC_SET_ENCRYPTION_POLICY, policy);
  close(fd);

  if (ret != 0) {
    fprintf(stderr, "error: setting policy for %s: %s\n", path,
            describe_set_policy_error(errno));
    return false;
  }
  return true;
}

/* Functions for various actions, return 0 on success, non-zero on failure. */

// Get the descriptor for some key data passed via stdin. Provided key data must
// have length FSCRYPT_MAX_KEY_SIZE. Output will be formatted as hex.
static int cmd_get_descriptor(int argc, char *const argv[]) {
  handle_no_options(&argc, &argv);
  if (argc != 0) {
    fputs("error: unexpected arguments\n", stderr);
    return EXIT_FAILURE;
  }

  int ret = EXIT_SUCCESS;
  uint8_t key[FSCRYPT_MAX_KEY_SIZE];

  if (read_key(key)) {
    ret = EXIT_FAILURE;
    goto cleanup;
  }

  char descriptor[FSCRYPT_KEY_DESCRIPTOR_HEX_SIZE];
  compute_descriptor(key, descriptor);
  puts(descriptor);

cleanup:
  secure_wipe(key, FSCRYPT_MAX_KEY_SIZE);
  return ret;
}

// Insert a key read from stdin into the current session keyring. This has the
// effect of unlocking files encrypted with that key.
static int cmd_insert_key(int argc, char *const argv[]) {
  // Which prefix will be used in this program, changed via command line flag.
  const char *service_prefix = FSCRYPT_KEY_DESC_PREFIX;

  static const struct option insert_key_options[] = {
      {"ext4", no_argument, NULL, 'e'},
      {"f2fs", no_argument, NULL, 'f'},
      {NULL, 0, NULL, 0}};

  int ch;
  while ((ch = getopt_long(argc, argv, "", insert_key_options, NULL)) != -1) {
    switch (ch) {
      case 'e':
        service_prefix = EXT4_KEY_DESC_PREFIX;
        break;
      case 'f':
        service_prefix = F2FS_KEY_DESC_PREFIX;
        break;
      default:
        usage(stderr);
    }
  }
  if (argc != optind) {
    fputs("error: unexpected arguments\n", stderr);
    return EXIT_FAILURE;
  }

  int ret = EXIT_SUCCESS;
  uint8_t key[FSCRYPT_MAX_KEY_SIZE];
  if (read_key(key)) {
    ret = EXIT_FAILURE;
    goto cleanup;
  }

  char descriptor[FSCRYPT_KEY_DESCRIPTOR_HEX_SIZE];
  compute_descriptor(key, descriptor);
  if (insert_logon_key(key, descriptor, service_prefix)) {
    fprintf(stderr, "error: inserting key: %s\n", strerror(errno));
    ret = EXIT_FAILURE;
    goto cleanup;
  }
  puts(descriptor);

cleanup:
  secure_wipe(key, FSCRYPT_MAX_KEY_SIZE);
  return ret;
}

static int cmd_add_key(int argc, char *const argv[]) {
  handle_no_options(&argc, &argv);
  if (argc != 1) {
    fputs("error: must specify a single mountpoint\n", stderr);
    return EXIT_FAILURE;
  }
  const char *mountpoint = argv[0];

  struct fscrypt_add_key_arg *arg =
      calloc(sizeof(*arg) + FSCRYPT_MAX_KEY_SIZE, 1);
  if (!arg) {
    fputs("error: failed to allocate memory\n", stderr);
    return EXIT_FAILURE;
  }

  int status = EXIT_FAILURE;
  if (read_key(arg->raw)) {
    goto cleanup;
  }
  arg->raw_size = FSCRYPT_MAX_KEY_SIZE;
  arg->key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;

  int fd = open(mountpoint, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr, "error: opening %s: %s\n", mountpoint, strerror(errno));
    goto cleanup;
  }
  if (ioctl(fd, FS_IOC_ADD_ENCRYPTION_KEY, arg) != 0) {
    fprintf(stderr, "error: adding key to %s: %s\n", mountpoint,
            describe_fscrypt_v2_error(errno));
    close(fd);
    goto cleanup;
  }
  close(fd);

  char identifier_hex[FSCRYPT_KEY_IDENTIFIER_HEX_SIZE];
  bytes_to_hex(arg->key_spec.u.identifier, FSCRYPT_KEY_IDENTIFIER_SIZE,
               identifier_hex);
  puts(identifier_hex);
  status = EXIT_SUCCESS;
cleanup:
  secure_wipe(arg->raw, FSCRYPT_MAX_KEY_SIZE);
  free(arg);
  return status;
}

static int cmd_remove_key(int argc, char *const argv[]) {
  int ioc = FS_IOC_REMOVE_ENCRYPTION_KEY;

  static const struct option remove_key_options[] = {
      {"all-users", no_argument, NULL, OPT_ALL_USERS}, {NULL, 0, NULL, 0}};

  int ch;
  while ((ch = getopt_long(argc, argv, "", remove_key_options, NULL)) != -1) {
    switch (ch) {
      case OPT_ALL_USERS:
        ioc = FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS;
        break;
      default:
        usage(stderr);
    }
  }
  argc -= optind;
  argv += optind;
  if (argc != 2) {
    fputs("error: must specify a key identifier and a mountpoint\n", stderr);
    return EXIT_FAILURE;
  }
  const char *key_identifier = argv[0];
  const char *mountpoint = argv[1];

  struct fscrypt_remove_key_arg arg = {};
  if (!build_key_specifier(key_identifier, &arg.key_spec)) {
    return EXIT_FAILURE;
  }

  int fd = open(mountpoint, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr, "error: opening %s: %s\n", mountpoint, strerror(errno));
    return EXIT_FAILURE;
  }
  int ret = ioctl(fd, ioc, &arg);
  close(fd);
  if (ret != 0) {
    fprintf(stderr, "error: removing key: %s\n",
            describe_fscrypt_v2_error(errno));
    return EXIT_FAILURE;
  }

  if (arg.removal_status_flags & FSCRYPT_KEY_REMOVAL_STATUS_FLAG_OTHER_USERS) {
    printf("warning: other users still have this key added\n");
  } else if (arg.removal_status_flags &
             FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY) {
    printf("warning: some files using this key are still in-use\n");
  }
  return EXIT_SUCCESS;
}

static int cmd_key_status(int argc, char *const argv[]) {
  handle_no_options(&argc, &argv);
  if (argc != 2) {
    fputs("error: must specify a key identifier and a mountpoint\n", stderr);
    return EXIT_FAILURE;
  }
  const char *key_identifier = argv[0];
  const char *mountpoint = argv[1];

  struct fscrypt_get_key_status_arg arg = {};
  if (!build_key_specifier(key_identifier, &arg.key_spec)) {
    return EXIT_FAILURE;
  }

  int fd = open(mountpoint, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr, "error: opening %s: %s\n", mountpoint, strerror(errno));
    return EXIT_FAILURE;
  }
  int ret = ioctl(fd, FS_IOC_GET_ENCRYPTION_KEY_STATUS, &arg);
  close(fd);
  if (ret != 0) {
    fprintf(stderr, "error: getting key status: %s\n",
            describe_fscrypt_v2_error(errno));
    return EXIT_FAILURE;
  }

  switch (arg.status) {
    case FSCRYPT_KEY_STATUS_PRESENT:
      printf("Present");
      if (arg.user_count || arg.status_flags) {
        printf(" (user_count=%u", arg.user_count);
        if (arg.status_flags & FSCRYPT_KEY_STATUS_FLAG_ADDED_BY_SELF) {
          printf(", added_by_self");
        }
        arg.status_flags &= ~FSCRYPT_KEY_STATUS_FLAG_ADDED_BY_SELF;
        if (arg.status_flags) {
          printf(", unknown_flags=0x%08x", arg.status_flags);
        }
        printf(")");
      }
      printf("\n");
      break;
    case FSCRYPT_KEY_STATUS_ABSENT:
      printf("Absent\n");
      break;
    case FSCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED:
      printf("Incompletely removed\n");
      break;
    default:
      printf("Unknown status (%u)\n", arg.status);
      break;
  }
  return EXIT_SUCCESS;
}

static void show_encryption_mode(uint8_t mode_num, const char *type) {
  const char *str = mode_to_string(mode_num);
  if (str != NULL) {
    printf("\t%s encryption mode: %s\n", type, str);
  } else {
    printf("\t%s encryption mode: Unknown (%d)\n", type, mode_num);
  }
}

static void show_policy_flags(uint8_t flags) {
  printf("\tFlags: PAD_%d",
         padding_values[flags & FSCRYPT_POLICY_FLAGS_PAD_MASK]);
  flags &= ~FSCRYPT_POLICY_FLAGS_PAD_MASK;

  if (flags & FSCRYPT_POLICY_FLAG_DIRECT_KEY) {
    printf(", DIRECT_KEY");
    flags &= ~FSCRYPT_POLICY_FLAG_DIRECT_KEY;
  }

  if (flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64) {
    printf(", IV_INO_LBLK_64");
    flags &= ~FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64;
  }

  if (flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32) {
    printf(", IV_INO_LBLK_32");
    flags &= ~FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32;
  }

  if (flags != 0) {
    printf(", Unknown (%02x)", flags);
  }

  printf("\n");
}

static void show_v1_encryption_policy(const struct fscrypt_policy_v1 *policy) {
  char descriptor_hex[FSCRYPT_KEY_DESCRIPTOR_HEX_SIZE];
  bytes_to_hex(policy->master_key_descriptor, FSCRYPT_KEY_DESCRIPTOR_SIZE,
               descriptor_hex);
  printf("\tMaster key descriptor: %s\n", descriptor_hex);
  show_encryption_mode(policy->contents_encryption_mode, "Contents");
  show_encryption_mode(policy->filenames_encryption_mode, "Filenames");
  show_policy_flags(policy->flags);
}

static void show_v2_encryption_policy(const struct fscrypt_policy_v2 *policy) {
  char identifier_hex[FSCRYPT_KEY_IDENTIFIER_HEX_SIZE];
  bytes_to_hex(policy->master_key_identifier, FSCRYPT_KEY_IDENTIFIER_SIZE,
               identifier_hex);
  printf("\tMaster key identifier: %s\n", identifier_hex);
  show_encryption_mode(policy->contents_encryption_mode, "Contents");
  show_encryption_mode(policy->filenames_encryption_mode, "Filenames");
  show_policy_flags(policy->flags);
}

// For a specified file or directory with encryption enabled, print the
// corresponding policy to stdout.
static int cmd_get_policy(int argc, char *const argv[]) {
  handle_no_options(&argc, &argv);
  if (argc != 1) {
    fputs("error: must specify a single file or directory\n", stderr);
    return EXIT_FAILURE;
  }
  const char *path = argv[0];

  struct fscrypt_get_policy_ex_arg arg = {};
  if (!get_policy(path, &arg)) {
    return EXIT_FAILURE;
  }

  printf("Encryption policy for %s:\n", path);
  printf("\tPolicy version: %d\n",
         // Hide the quirk of FSCRYPT_POLICY_V1 really being 0.
         arg.policy.version == FSCRYPT_POLICY_V1 ? 1 : arg.policy.version);
  switch (arg.policy.version) {
    case FSCRYPT_POLICY_V1:
      show_v1_encryption_policy(&arg.policy.v1);
      break;
    case FSCRYPT_POLICY_V2:
      show_v2_encryption_policy(&arg.policy.v2);
      break;
  }

  return EXIT_SUCCESS;
}

// Apply an encryption policy to the specified directory.  The encryption
// options can be overridden by command-line options.
static int cmd_set_policy(int argc, char *const argv[]) {
  uint8_t contents_encryption_mode = FSCRYPT_MODE_AES_256_XTS;
  uint8_t filenames_encryption_mode = FSCRYPT_MODE_AES_256_CTS;
  // Default to maximum zero-padding to leak less info about filename lengths.
  uint8_t flags = FSCRYPT_POLICY_FLAGS_PAD_32;

  static const struct option set_policy_options[] = {
      {"contents", required_argument, NULL, OPT_CONTENTS},
      {"filenames", required_argument, NULL, OPT_FILENAMES},
      {"padding", required_argument, NULL, OPT_PADDING},
      {"direct-key", no_argument, NULL, OPT_DIRECT_KEY},
      {"iv-ino-lblk-64", no_argument, NULL, OPT_IV_INO_LBLK_64},
      {"iv-ino-lblk-32", no_argument, NULL, OPT_IV_INO_LBLK_32},
      {NULL, 0, NULL, 0}};

  int ch, padding_flag;
  while ((ch = getopt_long(argc, argv, "", set_policy_options, NULL)) != -1) {
    switch (ch) {
      case OPT_CONTENTS:
        if (!string_to_mode(optarg, &contents_encryption_mode)) {
          fprintf(stderr, "error: invalid contents mode: %s\n", optarg);
          return EXIT_FAILURE;
        }
        break;
      case OPT_FILENAMES:
        if (!string_to_mode(optarg, &filenames_encryption_mode)) {
          fprintf(stderr, "error: invalid filenames mode: %s\n", optarg);
          return EXIT_FAILURE;
        }
        break;
      case OPT_PADDING:
        padding_flag = string_to_padding_flag(optarg);
        if (padding_flag < 0) {
          fprintf(stderr, "error: invalid padding: %s\n", optarg);
          return EXIT_FAILURE;
        }
        flags &= ~FSCRYPT_POLICY_FLAGS_PAD_MASK;
        flags |= padding_flag;
        break;
      case OPT_DIRECT_KEY:
        flags |= FSCRYPT_POLICY_FLAG_DIRECT_KEY;
        break;
      case OPT_IV_INO_LBLK_64:
        flags |= FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64;
        break;
      case OPT_IV_INO_LBLK_32:
        printf("warning: --iv-ino-lblk-32 should normally not be used\n");
        flags |= FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32;
        break;
      default:
        usage(stderr);
    }
  }
  argc -= optind;
  argv += optind;
  if (argc != 2) {
    fputs("error: must specify a key and a directory\n", stderr);
    return EXIT_FAILURE;
  }
  const char *key_specifier = argv[0];
  const char *path = argv[1];

  // Initialize the encryption policy struct.  Determine the policy version by
  // the length of the key specifier.  v1 uses a key descriptor of 8 bytes (16
  // hex chars).  v2 uses a key identifier of 16 bytes (32 hex chars).
  union fscrypt_policy policy = {};
  switch (strlen(key_specifier) + 1 /* count the null terminator */) {
    case FSCRYPT_KEY_DESCRIPTOR_HEX_SIZE:
      policy.version = FSCRYPT_POLICY_V1;
      if (!hex_to_bytes(key_specifier, policy.v1.master_key_descriptor,
                        FSCRYPT_KEY_DESCRIPTOR_SIZE)) {
        fprintf(stderr, "error: invalid key descriptor: %s\n", key_specifier);
        return EXIT_FAILURE;
      }
      policy.v1.contents_encryption_mode = contents_encryption_mode;
      policy.v1.filenames_encryption_mode = filenames_encryption_mode;
      policy.v1.flags = flags;
      break;
    case FSCRYPT_KEY_IDENTIFIER_HEX_SIZE:
      policy.version = FSCRYPT_POLICY_V2;
      if (!hex_to_bytes(key_specifier, policy.v2.master_key_identifier,
                        FSCRYPT_KEY_IDENTIFIER_SIZE)) {
        fprintf(stderr, "error: invalid key identifier: %s\n", key_specifier);
        return EXIT_FAILURE;
      }
      policy.v2.contents_encryption_mode = contents_encryption_mode;
      policy.v2.filenames_encryption_mode = filenames_encryption_mode;
      policy.v2.flags = flags;
      break;
    default:
      fprintf(stderr, "error: invalid key specifier: %s\n", key_specifier);
      return EXIT_FAILURE;
  }

  // Set the encryption policy on the directory.
  if (!set_policy(path, &policy)) {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

static const struct {
  const char *name;
  int (*func)(int argc, char *const argv[]);
} commands[] = {
    {"get_descriptor", cmd_get_descriptor},
    {"insert_key", cmd_insert_key},
    {"add_key", cmd_add_key},
    {"remove_key", cmd_remove_key},
    {"key_status", cmd_key_status},
    {"get_policy", cmd_get_policy},
    {"set_policy", cmd_set_policy},
};

int main(int argc, char *const argv[]) {
  // Check for the help or version options.
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) {
      break;
    }
    if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      usage(stdout);
    }
    if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
      puts(VERSION);
      return EXIT_SUCCESS;
    }
  }

  if (argc < 2) {
    fputs("error: no command specified\n", stderr);
    usage(stderr);
  }
  const char *command = argv[1];

  for (size_t i = 0; i < ARRAY_SIZE(commands); i++) {
    if (strcmp(command, commands[i].name) == 0) {
      return commands[i].func(argc - 1, argv + 1);
    }
  }

  fprintf(stderr, "error: invalid command: %s\n", command);
  usage(stderr);
}
