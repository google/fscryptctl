# fscryptctl

`fscryptctl` is a low-level tool written in C that handles raw keys and manages
policies for [Linux filesystem
encryption](https://www.kernel.org/doc/html/latest/filesystems/fscrypt.html),
specifically the "fscrypt" kernel interface which is supported by the ext4,
f2fs, and UBIFS filesystems.

`fscryptctl` is mainly intended for embedded systems which can't use the
full-featured [`fscrypt` tool](https://github.com/google/fscrypt), or for
testing or experimenting with the kernel interface to Linux filesystem
encryption.  `fscryptctl` does *not* handle key generation, key stretching, key
wrapping, or PAM integration.  Most users should use the `fscrypt` tool instead,
which supports these features and generally is much easier to use.

As `fscryptctl` is intended for advanced users, you should read the [kernel
documentation for filesystem
encryption](https://www.kernel.org/doc/html/latest/filesystems/fscrypt.html)
before using `fscryptctl`.

## Table of Contents

- [Building and Installing](#building-and-installing)
- [Runtime Dependencies](#runtime-dependencies)
- [Features](#features)
- [Example Usage](#example-usage)
- [Contributing](#contributing)
- [Legal](#legal)

## Building and Installing

To build `fscryptctl`, run `make`.  The only build dependencies are GNU Make and
a C compiler (only C99 is needed).

To install `fscryptctl`, run `sudo make install`.

See the `Makefile` for compilation and installation options.

## Runtime Dependencies

`fscryptctl` doesn't link to any libraries (other than libc), so its only
runtime dependencies are the kernel and filesystem support for encryption.  In
most cases that means the kernel must have been built `CONFIG_FS_ENCRYPTION=y`,
and a command like `tune2fs -O encrypt` must have been run on the filesystem.
For more information about the kernel and filesystem prerequisites, see the
[`fscrypt`
documentation](https://github.com/google/fscrypt#runtime-dependencies),
including the [troubleshooting
tips](https://github.com/google/fscrypt#getting-encryption-not-enabled-on-an-ext4-filesystem).

## Features

`fscryptctl` has the following commands:

* `fscryptctl add_key` - add an encryption key to a filesystem
* `fscryptctl remove_key` - remove an encryption key from a filesystem
* `fscryptctl key_status` - get the status of an encryption key on a filesystem
* `fscryptctl get_policy` - get the encryption policy of a file or directory
* `fscryptctl set_policy` - set the encryption policy of an empty directory

There are also two deprecated commands:

* `fscryptctl insert_key` - add a v1 policy key to the session keyring
* `fscryptctl get_descriptor` - compute key descriptor for a v1 policy key

Run `fscryptctl --help` for full usage details.

The `add_key` and `insert_key` commands accept the encryption key in binary on
standard input.  It is critical that this be a real cryptographic key (and not a
passphrase, for example), since `fscryptctl` doesn't do key stretching itself.
Obviously, don't store the raw encryption key alongside the encrypted files.
(If you need support for passphrases, use `fscrypt` instead of `fscryptctl`.)

`fscryptctl` supports both v1 and v2 encryption policies.  (An "encryption
policy" refers to the way in which a directory is encrypted: a reference to a
key, plus the encryption options.)  v2 encryption policies are supported by
kernel 5.4 and later, and they should be used whenever possible, since they have
various security and usability improvements over v1.  See the [kernel
documentation](https://www.kernel.org/doc/html/latest/filesystems/fscrypt.html#limitations-of-v1-policies)
for more details.

From the `fscryptctl` user's perspective, v1 and v2 policies differ primarily in
how encryption keys are managed.  Keys for v1 policies are placed into the Linux
session keyring by `fscryptctl insert_key` and are identified by 16-character
"key descriptors".  Keys for v2 policies are placed in a filesystem keyring
using `fscryptctl add_key` and are identified by 32-character "key identifiers".

`fscryptctl set_policy` accepts either a key descriptor, in which case it sets a
v1 policy, or a key identifier, in which case it sets a v2 policy.  So
effectively, `fscryptctl set_policy` will set a v1 policy if `fscryptctl
insert_key` was used, or a v2 policy if `fscryptctl add_key` was used.

## Example Usage

```shell
# Create and mount an ext4 filesystem that supports encryption.
# (Alternatively, use `tune2fs -O encrypt` on an existing ext4 filesystem.)
# (For f2fs, use `mkfs.f2fs -O encrypt` or `fsck.f2fs -O encrypt`.)
> mkfs.ext4 -O encrypt /dev/vdb
> mount /dev/vdb /mnt

# Generate a random 512-bit key and store it in a file.
> head -c 64 /dev/urandom > /tmp/key

# Add the key to the filesystem.
> fscryptctl add_key /mnt < /tmp/key
f12fccad977328d20a16c79627787a1c

# Get the status of the key on the filesystem.
> fscryptctl key_status f12fccad977328d20a16c79627787a1c /mnt
Present (user_count=1, added_by_self)

# Create an encrypted directory that uses the key.
> fscryptctl set_policy f12fccad977328d20a16c79627787a1c /mnt/dir

# Show the directory's encryption policy that was just set.
> fscryptctl get_policy /mnt/dir
Encryption policy for /mnt/dir:
        Policy version: 2
        Master key identifier: f12fccad977328d20a16c79627787a1c
        Contents encryption mode: AES-256-XTS
        Filenames encryption mode: AES-256-CTS
        Flags: PAD_32

# Create some files in the encrypted directory.
> echo foo > /mnt/dir/foo
> mkdir /mnt/dir/bar

# Remove the encryption key from the filesystem.
# (Alternatively, unmounting the filesystem will remove the key too.)
> fscryptctl remove_key f12fccad977328d20a16c79627787a1c /mnt

# Get the status of the key on the filesystem.
> fscryptctl key_status f12fccad977328d20a16c79627787a1c /mnt
Absent

# The directory is now locked.  So the filenames are shown in encrypted form,
# and files can't be opened or created.
> ls /mnt/dir
AcbnATV97HZzxlmWNoErWS8QkdgTzMzbPU5hjs7XwvyralC5fQCtQA
qXT50ks2,3RzC8kqJ5FvnHgxS6oL2UDa8nsVkCFmoUQQygA3nWzxfA
> cat /mnt/dir/qXT50ks2,3RzC8kqJ5FvnHgxS6oL2UDa8nsVkCFmoUQQygA3nWzxfA
cat: /mnt/dir/qXT50ks2,3RzC8kqJ5FvnHgxS6oL2UDa8nsVkCFmoUQQygA3nWzxfA: Required key not available
> mkdir /mnt/dir/foobar
mkdir: cannot create directory ‘/mnt/dir/foobar’: Required key not available

# Re-adding the key restores access to the files.
> fscryptctl add_key /mnt < /tmp/key
f12fccad977328d20a16c79627787a1c
> ls /mnt/dir
bar foo
> cat /mnt/dir/foo
foo
```

## Contributing

We would love to accept your contributions to `fscryptctl`.  See the
`CONTRIBUTING.md` file for more information.

## Legal

Copyright 2017, 2020 Google LLC.  Licensed under the
[Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0); see the
`LICENSE` file for more information.

Authors: Joe Richey (joerichey@google.com),
         Eric Biggers (ebiggers@google.com)

This is not an official Google product.
