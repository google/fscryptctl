# fscryptctl

<!-- TODO: Insert link to fscrypt when it is released -->
`fscryptctl` is a low-level tool written in C that handles raw keys and manages
policies for [Linux filesystem encryption](https://lwn.net/Articles/639427). For
a tool that presents a higher level interface and manages metadata, key
generation, key wrapping, PAM integration, and passphrase hashing, see
`fscrypt`.

To use `fscryptctl`, you must have a filesystem with encryption enabled and a
kernel that supports reading/writing from that filesystem. Currently,
[ext4](https://en.wikipedia.org/wiki/Ext4),
[F2FS](https://en.wikipedia.org/wiki/F2FS), and
[UBIFS](https://en.wikipedia.org/wiki/UBIFS) support Linux filesystem
encryption. Ext4 has supported Linux filesystem encryption
[since v4.1](https://lwn.net/Articles/639427), F2FS
[added support in v4.2](https://lwn.net/Articles/649652), and UBIFS
[added support in v4.10](https://lwn.net/Articles/707900). Note that only
certain configurations of the Linux kernel enable encryption, and other
filesystems may add support for encryption. As the kernel uses a common
userspace interface, this tool will work with existing and future filesystems
which add support for encryption.

## Features

This tool aims to improve upon the work in
[e4crypt](http://man7.org/linux/man-pages/man8/e4crypt.8.html) with `fscryptctl`
providing a smaller and simpler interface. It only supports the minimal
functionality required to use filesystem encryption.  It supports the following
actions:
*   Getting the key descriptor for a provided key
*   Inserting a provided key into the keyring (with optional legacy flags)
*   Querying the encryption policy (i.e. key descriptor) for a file or directory
*   Setting an encryption policy on a directory

## Building

<!-- TODO: Change git clone URL before public release -->
Get the source by running `git clone [REDACTED]`.
Run `make` to build the executable `fscryptctl`. The only build dependencies are
`make` and a C compiler.

## Running and Installing

`fscryptctl` is a standalone binary, so it will not have any runtime
dependencies. It just needs to have support for filesystem encryption and for
the `keyctl()` and `add_key()` syscalls, which will be available on any kernel
new enough to support filesystem encryption.

Run `fscryptctl --help` to see the full usage and description of the available
commands and flags. Installing the tool just requires placing it in your path or
running `sudo make install` (set `DESTDIR` to install to a custom locations).

## Example Usage
```shell
# Make a key and store it in a file (where the key is 64 'c' bytes)
> printf "%64s" | tr ' ' 'c' > key.data
# Get the descriptor for the key
> ./fscryptctl get_descriptor < key.data
a8134316f6879ed4
# Insert the key into the keyring (using legacy ext4 options)
> ./fscryptctl insert_key --ext4 < key.data
a8134316f6879ed4
> keyctl show
Session Keyring
 827244259 --alswrv  416424 65534  keyring: _uid_ses.416424
 111054036 --alswrv  416424 65534   \_ keyring: _uid.416424
 227138126 --alsw-v  416424  5000   \_ logon: ext4:a8134316f6879ed4

# Remove the key from the keyring
> keyctl unlink 227138126
# Make a test directory on a filesystem that supports encryption
> mkdir /mnt/disks/encrypted/test
# Setup an encryption policy on that directory
> ./fscryptctl set_policy a8134316f6879ed4 /mnt/disks/encrypted/test
> ./fscryptctl get_policy /mnt/disks/encrypted/test
a8134316f6879ed4

# We cannot create files in the directory without the key
> echo "Hello World!" > /mnt/disks/encrypted/test/foo.txt
An error occurred while redirecting file '/mnt/disks/encrypted/test/foo.txt'
open: No such file or directory
> ./fscryptctl insert_key --ext4 < key.data
a8134316f6879ed4
# Now we can make the file and write data to it
> echo "Hello World!" > /mnt/disks/encrypted/test/foo.txt
> ls -lA /mnt/disks/encrypted/test/
total 4
-rw-rw-r-- 1 joerichey joerichey 12 Mar 30 20:00 foo.txt
> cat /mnt/disks/encrypted/test/foo.txt
Hello World!

# Now we remove the key, remount the filesystem, and see the encrypted data
> keyctl show
Session Keyring
1047869403 --alswrv   1001  1002  keyring: _ses
 967765418 --alswrv   1001 65534   \_ keyring: _uid.1001
1009690551 --alsw-v   1001  1002   \_ logon: ext4:a8134316f6879ed4
> keyctl unlink 1009690551
1 links removed
> sudo umount /mnt/disks/encrypted
> sudo mount /mnt/disks/encrypted
> ls -lA /mnt/disks/encrypted/test/
total 4
-rw-rw-r-- 1 joerichey joerichey 13 Mar 30 20:00 wnJP+VX33Y6OSbN08+,jtQXK9yMHm8CFcI64CxDFPxL
> cat /mnt/disks/encrypted/test/wnJP+VX33Y6OSbN08+,jtQXK9yMHm8CFcI64CxDFPxL
cat: /mnt/disks/encrypted/test/wnJP+VX33Y6OSbN08+,jtQXK9yMHm8CFcI64CxDFPxL: Required key not available

# Reinserting the key restores access to the data
> ./fscryptctl insert_key --ext4 < key.data
a8134316f6879ed4
> ls -lA /mnt/disks/encrypted/test/
total 4
-rw-rw-r-- 1 joerichey joerichey 12 Mar 30 20:00 foo.txt
> cat /mnt/disks/encrypted/test/foo.txt
Hello World!
```

## Contributing

If you are making changes to the fscryptctl component, the only additional
command you will need is `make format` which formats all of the C code. This
command should be run before committing any changes and requires `clang-format`
to be installed (`sudo apt-get install clang-format`).

## Known Issues

None so far!

## License

Copyright 2017 Google Inc.

Author: Joe Richey <joerichey@google.com>

Distributed under the
[Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0); see the
`LICENSE` file for more information.
