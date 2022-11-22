# fscryptctl release notes

## Version 1.0.0

`fscryptctl` is now stable with release v1.0.0.

### Minimum kernel version

As `fscryptctl` now uses v2 encryption policies, it must be used with Linux
kernel 5.4 or later.

### New features

* [Support for v2 encryption
  policies](https://github.com/google/fscryptctl/pull/16), fixing several user
  issues:
    * Increased security around key derivation.  Compromise of per-file key no
      longer leads to master key compromise.
    * Removed any dependencies on user/session keyrings.
    * Unlocked directories are now visible to all users/processes (provided they
      have appropriate permissions).
    * Removed potential Denial-of-Service attack by non-root users.
* All key operations are now performed relative to a mountpoint.
* **New commands**
    * `fscryptctl remove_key`: all users can now easily remove keys.
        * The root-only option `--all-users` can be used to remove a key for all
          users at once.
    * `fscryptctl key_status`: the status of a key can be checked.
* `fscryptctl insert_key` renamed to `fscryptctl add_key`.
* Key identifiers are now 32-character hex strings (16 bytes).
    * Pre-v1 `fscryptctl` referred to key "descriptors" which were 16-character
      hex strings (8 bytes).
* Optimization policy flags:
    * `--direct-key`: Optimizes for [Adiantum
      encryption](https://github.com/google/adiantum)
    * `--iv-ino-lblk-64`: Optimizes for UFS [inline crypto
      hardware](https://lwn.net/Articles/790556/)

### Removed features

* `fscryptctl` no longer supports v1 encryption policies.
    * These policies can be insecure.
    * These policies are hard to use correctly.
    * These policies have different semantics from v2 policies, making it hard
      to have a single interface to both.
* Users wishing to continue using v1 policies should use a pre-v1.0.0 release of
  `fscryptctl`.

## Version 0.1.0

Initial release.

Note: this release of `fscryptctl` only includes support for v1 policies.  For
v2 policies, users will need to use v1.0.0 or later.

For more information about v1 and v2 encryption policies, see [the Linux kernel
documentation](https://www.kernel.org/doc/html/latest/filesystems/fscrypt.html).
