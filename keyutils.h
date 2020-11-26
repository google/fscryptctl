/*
 * keyutils.h - stripped-down replacement for libkeyutils
 *
 * Copyright 2020 Google LLC
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

#ifndef KEYUTILS_H
#define KEYUTILS_H

#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef int32_t key_serial_t;
#define KEYCTL_GET_KEYRING_ID 0     /* ask for a keyring's ID */
#define KEY_SPEC_SESSION_KEYRING -3 /* current session keyring */

static inline key_serial_t add_key(const char *type, const char *description,
                                   const void *payload, size_t plen,
                                   key_serial_t ringid) {
  return syscall(__NR_add_key, type, description, payload, plen, ringid);
}

static inline key_serial_t keyctl_get_keyring_ID(key_serial_t id, int create) {
  return syscall(__NR_keyctl, KEYCTL_GET_KEYRING_ID, id, create);
}

#endif /* KEYUTILS_H */
