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

## Building

<!-- TODO: Change git clone URL before public release -->
Get the source by running `git clone [REDACTED]`.
Run `make` to build the executable `fscryptctl`. The only build dependencies are
`make` and a C compiler.

## Running and Installing

`fscryptctl` is a standalone binary, so it will not have any runtime
dependencies. Installing it just requires placing it in your path or running
`sudo make install` (set `DESTDIR` to install to a custom locations).

## Example Usage
```shell
# Getting a key descriptor (where the key is 64 'c' bytes)
> printf "%64s" | tr ' ' 'c' | ./fscryptctl get_descriptor
a8134316f6879ed4
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
