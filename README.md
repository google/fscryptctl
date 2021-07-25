# fscryptctl

[![Build Status](https://github.com/google/fscryptctl/workflows/CI/badge.svg)](https://github.com/google/fscryptctl/actions?query=workflow%3ACI+branch%3Amaster)
[![License](https://img.shields.io/badge/LICENSE-Apache2.0-ff69b4.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

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

To build, run `make`.  The build dependencies are GNU Make, a C compiler (only
C99 is needed), and [pandoc](https://pandoc.org/).

To install, run `sudo make install`.

If you don't want to build and install the `fscryptctl.1` manual page, you can
instead run `make fscryptctl` and `sudo make install-bin`.  This will build and
install the `fscryptctl` binary only, avoiding the build dependency on `pandoc`.

See the `Makefile` for compilation and installation options.

## Runtime Dependencies

`fscryptctl` doesn't link to any libraries (other than libc), so its only
runtime dependencies are the kernel and filesystem support for encryption.  In
most cases that means the kernel must have been built `CONFIG_FS_ENCRYPTION=y`,
and a command like `tune2fs -O encrypt` must have been run on the filesystem.

Since v1.0, `fscryptctl` only supports v2 filesystem encryption policies.  This
means that it must be used with Linux kernel 5.4 or later.   If you need support
for v1 encryption policies, use an earlier version of `fscryptctl`.  However, be
aware that v1 had some significant usability and security limitations.

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

For full usage details, see the manual page (`man fscryptctl`), or alternatively
run `fscryptctl --help`.

The `add_key` command, by default, accepts the encryption key in binary on
standard input.
It is critical that this be a real cryptographic key (and not a passphrase, for
example), since `fscryptctl` doesn't do key stretching itself.  Obviously, don't
store the raw encryption key alongside the encrypted files.  (If you need
support for passphrases, use `fscrypt` instead of `fscryptctl`.)

Alternatively, `add_key --serial=$serial` will instruct the kernel to
extract the kernel material from an existing key of type "fscrypt-provisioning"
with the specified $serial (The ID returned and used by keyctl(1)).

After running the `add_key` command to add an encryption key to a filesystem,
you can use the `set_policy` command to create an encrypted directory on that
filesystem.  The encryption key is specified by the 32-character hex "key
identifier" that was printed by `add_key`.  The directory must be empty.

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
