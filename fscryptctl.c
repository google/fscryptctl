/*
 * fscryptctl.c - Low-level tool for managing keys and policies for the
 *                fs/crypto/ kernel interface.
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

#define _GNU_SOURCE  // For O_CLOEXEC

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

#ifndef VERSION
// Update this on each new release, along with the NEWS.md file.
#define VERSION "v1.2.0"
#endif

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

static void secure_wipe(void *v, size_t n) {
#ifdef explicit_bzero
  explicit_bzero(v, n);
#else
  volatile uint8_t *p = v;
  while (n--) {
    *p++ = 0;
  }
#endif
}

// Although the kernel always allows 64-byte keys, it may allow shorter keys
// too, depending on the encryption mode(s) used.  The shortest key the kernel
// can ever accept is 16 bytes, which occurs when AES-128-CBC contents
// encryption is used.  However, when adding a key, fscryptctl doesn't know
// which encryption mode(s) will be used later.  So fscryptctl just allows all
// key lengths in the range [16, 64], and the kernel will return an error later
// if the key is too short for the encryption policy it is used for.
#define FSCRYPT_MIN_KEY_SIZE 16

#define FSCRYPT_KEY_DESCRIPTOR_HEX_SIZE ((2 * FSCRYPT_KEY_DESCRIPTOR_SIZE) + 1)
#define FSCRYPT_KEY_IDENTIFIER_HEX_SIZE ((2 * FSCRYPT_KEY_IDENTIFIER_SIZE) + 1)

// Human-readable strings for encryption modes, indexed by the encryption mode
static const char *const mode_strings[] = {
    [FSCRYPT_MODE_AES_256_XTS] = "AES-256-XTS",
    [FSCRYPT_MODE_AES_256_CTS] = "AES-256-CTS",
    [FSCRYPT_MODE_AES_128_CBC] = "AES-128-CBC",
    [FSCRYPT_MODE_AES_128_CTS] = "AES-128-CTS",
    [FSCRYPT_MODE_SM4_XTS] = "SM4-XTS",
    [FSCRYPT_MODE_SM4_CTS] = "SM4-CTS",
    [FSCRYPT_MODE_ADIANTUM] = "Adiantum",
    [FSCRYPT_MODE_AES_256_HCTR2] = "AES-256-HCTR2",
};

// Valid amounts of filename padding, indexed by the padding flag
static const int padding_values[] = {4, 8, 16, 32};

enum {
  OPT_ALL_USERS,
  OPT_CONTENTS,
  OPT_DATA_UNIT_SIZE,
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
      "  fscryptctl set_policy <key identifier> <directory>\n"
      "    Set up an encryption policy on the specified directory with the\n"
      "    specified key identifier.\n"
      "\nOptions:\n"
      "    -h, --help\n"
      "        print this help screen\n"
      "    -v, --version\n"
      "        print the version of fscrypt\n"
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
      "        --data-unit-size=<du_size>\n"
      "            data unit size in bytes (default: filesystem block size)\n"
      "\nNotes:\n"
      "  Keys are identified by 32-character hex strings (key identifiers).\n"
      "\n"
      "  Raw keys are given on stdin in binary and usually must be 64 bytes.\n"
      "\n"
      "  For more information, run `man fscryptctl`.\n",
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

static bool parse_data_unit_size(const char *str,
                                 uint8_t *log2_data_unit_size_ret) {
  int du_size = atoi(str);
  int bits = 0;

  while ((1LL << bits) < du_size) {
    bits++;
  }
  *log2_data_unit_size_ret = bits;
  return du_size > 1 && (1LL << bits) == du_size;
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

static ssize_t read_until_limit_or_eof(int fd, uint8_t *buf, size_t limit) {
  size_t pos = 0;
  while (pos < limit) {
    ssize_t ret = read(fd, &buf[pos], limit - pos);
    if (ret < 0) {
      return ret;
    }
    if (ret == 0) {
      break;
    }
    pos += ret;
  }
  return pos;
}

// Reads a raw key, of size at least FSCRYPT_MIN_KEY_SIZE bytes and at most
// FSCRYPT_MAX_KEY_SIZE bytes, from standard input into the provided buffer.
// On success, returns the key size in bytes.  On failure, returns 0.
//
// Note that we use read(STDIN_FILENO) directly rather than fread(stdin), to
// prevent the key from being copied into the internal buffer of the 'FILE *'.
static size_t read_key(uint8_t raw_key[FSCRYPT_MAX_KEY_SIZE]) {
  uint8_t buf[FSCRYPT_MAX_KEY_SIZE + 1];
  ssize_t ret = read_until_limit_or_eof(STDIN_FILENO, buf, sizeof(buf));
  if (ret < 0) {
    fprintf(stderr, "error: reading from stdin: %s\n", strerror(errno));
    ret = 0;
    goto cleanup;
  }
  if (ret < FSCRYPT_MIN_KEY_SIZE) {
    fprintf(stderr, "error: key was too short; it must be at least %d bytes\n",
            FSCRYPT_MIN_KEY_SIZE);
    ret = 0;
    goto cleanup;
  }
  if (ret > FSCRYPT_MAX_KEY_SIZE) {
    fprintf(stderr, "error: key was too long; it can be at most %d bytes\n",
            FSCRYPT_MAX_KEY_SIZE);
    ret = 0;
    goto cleanup;
  }
  memcpy(raw_key, buf, ret);
cleanup:
  secure_wipe(buf, sizeof(buf));
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
  close(fd);

  if (ret != 0) {
    fprintf(stderr, "error: getting policy for %s: %s\n", path,
            describe_get_policy_error(errno));
    return false;
  }
  return true;
}

static bool set_policy(const char *path,
                       const struct fscrypt_policy_v2 *policy) {
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

// -----------------------------------------------------------------------------
//                                 Commands
// -----------------------------------------------------------------------------

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
  arg->raw_size = read_key(arg->raw);
  if (arg->raw_size == 0) {
    goto cleanup;
  }
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
  secure_wipe(arg->raw, arg->raw_size);
  free(arg);
  return status;
}

static int cmd_remove_key(int argc, char *const argv[]) {
  unsigned long ioc = FS_IOC_REMOVE_ENCRYPTION_KEY;

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

  struct fscrypt_remove_key_arg arg = {0};
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

  struct fscrypt_get_key_status_arg arg = {0};
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
  if (policy->log2_data_unit_size) {
    printf("\tData unit size: %u\n", 1U << policy->log2_data_unit_size);
  } else {
    printf("\tData unit size: default\n");
  }
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

  struct fscrypt_get_policy_ex_arg arg = {0};
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
  uint8_t log2_data_unit_size = 0;

  static const struct option set_policy_options[] = {
      {"contents", required_argument, NULL, OPT_CONTENTS},
      {"filenames", required_argument, NULL, OPT_FILENAMES},
      {"padding", required_argument, NULL, OPT_PADDING},
      {"direct-key", no_argument, NULL, OPT_DIRECT_KEY},
      {"iv-ino-lblk-64", no_argument, NULL, OPT_IV_INO_LBLK_64},
      {"iv-ino-lblk-32", no_argument, NULL, OPT_IV_INO_LBLK_32},
      {"data-unit-size", required_argument, NULL, OPT_DATA_UNIT_SIZE},
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
      case OPT_DATA_UNIT_SIZE:
        if (!parse_data_unit_size(optarg, &log2_data_unit_size)) {
          fprintf(stderr, "error: invalid data unit size: %s\n", optarg);
          return EXIT_FAILURE;
        }
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
  const char *key_identifier = argv[0];
  const char *path = argv[1];

  // Initialize the encryption policy struct.
  struct fscrypt_policy_v2 policy = {.version = FSCRYPT_POLICY_V2};
  if (!hex_to_bytes(key_identifier, policy.master_key_identifier,
                    FSCRYPT_KEY_IDENTIFIER_SIZE)) {
    fprintf(stderr, "error: invalid key identifier: %s\n", key_identifier);
    return EXIT_FAILURE;
  }
  policy.contents_encryption_mode = contents_encryption_mode;
  policy.filenames_encryption_mode = filenames_encryption_mode;
  policy.flags = flags;
  policy.log2_data_unit_size = log2_data_unit_size;

  // Set the encryption policy on the directory.
  if (!set_policy(path, &policy)) {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

// -----------------------------------------------------------------------------
//                            The main() function
// -----------------------------------------------------------------------------

static const struct {
  const char *name;
  int (*func)(int argc, char *const argv[]);
} commands[] = {
    {"add_key", cmd_add_key},       {"remove_key", cmd_remove_key},
    {"key_status", cmd_key_status}, {"get_policy", cmd_get_policy},
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
