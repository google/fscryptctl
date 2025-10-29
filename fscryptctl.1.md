% FSCRYPTCTL(1) fscryptctl | User Commands

# NAME

fscryptctl - low-level userspace tool for Linux filesystem encryption

# SYNOPSIS
**fscryptctl add_key** [*OPTION*...] *MOUNTPOINT*... \
**fscryptctl remove_key** [*OPTION*...] *KEY_IDENTIFIER* *MOUNTPOINT* \
**fscryptctl key_status** *KEY_IDENTIFIER* *MOUNTPOINT* \
**fscryptctl get_policy** *PATH* \
**fscryptctl set_policy** [*OPTION*...] *KEY_IDENTIFIER* *DIRECTORY*

# DESCRIPTION

**fscryptctl** is a low-level tool that handles raw keys and manages policies
for Linux filesystem encryption, specifically the "fscrypt" kernel interface
which is supported by some filesystems such as ext4 and f2fs.

**fscryptctl** is mainly intended for embedded systems which can't use the
full-featured **fscrypt** tool, or for testing or experimenting with the kernel
interface to Linux filesystem encryption.  **fscryptctl** does *not* handle key
generation, key stretching, key wrapping, or PAM integration.  Most users should
instead use the **fscrypt** tool, which supports these features and generally is
much easier to use.

This manual page focuses on documenting all **fscryptctl** subcommands and
options.  For examples and more information about the corresponding kernel
feature, see the references at the end of this page.

# OPTIONS

**fscryptctl** always accepts the following options:

**\-h**, **\-\-help**
:   Show the help, for either one subcommand or for all subcommands.

**\-v**, **\-\-version**
:   Show the version of **fscryptctl**.

# SUBCOMMANDS

## **fscryptctl add_key** [*OPTION*...] *MOUNTPOINT*

Add an encryption key to the given mounted filesystem.  This will "unlock" any
files and directories that are protected by the given key on the given
filesystem.  This is a thin wrapper around the `FS_IOC_ADD_ENCRYPTION_KEY`
ioctl.

The encryption key is read from standard input and must be given in raw binary.
This must be a real cryptographic key and *not* e.g. a password.

If successful, **fscryptctl add_key** will print the key identifier of the newly
added key; this will be a 32-character hex string which can be passed to other
**fscryptctl** commands.

Options accepted by **fscryptctl add_key**:

**\-\-hw\-wrapped\-key**
:   Add a hardware-wrapped key.  If this option is given, the key must be a
    hardware-wrapped key in ephemerally-wrapped form, rather than a raw key.

## **fscryptctl remove_key** [*OPTION*...] *KEY_IDENTIFIER* *MOUNTPOINT*

Remove an encryption key from the given mounted filesystem.

This is a thin wrapper around the `FS_IOC_REMOVE_ENCRYPTION_KEY` ioctl (or
`FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS`).  Normally, this removes the key and
"locks" any files or directories that are protected by it.  Some caveats apply
when any of these files or directories is still in-use, or when the user trying
to remove the key differs from the user(s) who added the key.  In general these
situations should be avoided, but for details on how they are handled, see the
Linux kernel documentation for `FS_IOC_REMOVE_ENCRYPTION_KEY`.

Options accepted by **fscryptctl remove_key**:

**\-\-all-users**
:   Remove all users' claims to the key rather than just the current user's.
    Requires root.

## **fscryptctl key_status** *KEY_IDENTIFIER* *MOUNTPOINT*

Get the status of an encryption key on the given mounted filesystem.  This is a
thin wrapper around the `FS_IOC_GET_ENCRYPTION_KEY_STATUS` ioctl.  The key
status will be one of the following:

* Present
* Absent
* Incompletely removed

In the "Present" case, some information about which users added the key will
also be shown.

**fscryptctl key_status** does not accept any options.

## **fscryptctl get_policy** *PATH*

Show the encryption policy of the given file or directory.  This is a thin
wrapper around the `FS_IOC_GET_ENCRYPTION_POLICY_EX` ioctl.

The "encryption policy" refers to the encryption key with which the file or
directory is protected, along with encryption options such as the ciphers used
for file contents and filenames encryption.

**fscryptctl get_policy** does not accept any options.

## **fscryptctl set_policy** [*OPTION*...] *KEY_IDENTIFIER* *DIRECTORY*

Set an encryption policy on the given directory.  This is a thin wrapper around
the `FS_IOC_SET_ENCRYPTION_POLICY` ioctl.

The encryption policy will use the given encryption key (specified by its key
identifier), along with any encryption options given.

The policy will be version 2.  Version 1 policies are no longer supported by
**fscryptctl**, except by **fscryptctl get_policy**.

Options accepted by **fscryptctl set_policy**:

**\-\-contents**=*MODE*
:   The cipher that will be used to encrypt file contents.  Valid options are
    AES-256-XTS, AES-128-CBC, SM4-XTS, and Adiantum.  Default is AES-256-XTS.

**\-\-filenames**=*MODE*
:   The cipher that will be used to encrypt filenames.  Valid options are
    AES-256-CTS, AES-128-CTS, SM4-CTS, Adiantum, and AES-256-HCTR2.  Default
    is AES-256-CTS.

**\-\-padding**=*BYTES*
:   The number of bytes to which encrypted filename lengths will be aligned
    in order to hide the lengths of the original filenames.  Valid options are
    4, 8, 16, and 32.  Default is 32.

**\-\-direct\-key**
:   Optimize for Adiantum encryption.  For details, see the Linux kernel
    documentation for `FSCRYPT_POLICY_FLAG_DIRECT_KEY`.

**\-\-iv\-ino\-lblk\-64**
:   Optimize for UFS inline encryption hardware.  For details, see the Linux
    kernel documentation for `FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64`.

**\-\-iv\-ino\-lblk\-32**
:   Optimize for eMMC inline encryption hardware.  For details, see the Linux
    kernel documentation for `FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32`.

**\-\-data\-unit\-size**=*DU_SIZE*
:   Select the crypto data unit size, i.e. the granularity of file contents
    encryption, in bytes.

# SEE ALSO

* [**fscryptctl** README
  file](https://github.com/google/fscryptctl/blob/master/README.md)

* [Linux kernel documentation for filesystem
  encryption](https://docs.kernel.org/filesystems/fscrypt.html)

* [**fscrypt** tool, recommended for most users over
  fscryptctl](https://github.com/google/fscrypt)
