#
# Copyright 2017, 2020 Google LLC
#
# Authors: Joe Richey (joerichey@google.com),
#          Eric Biggers (ebiggers@google.com)
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
#

"""This is a pytest module which tests the fscryptctl binary.

The fscryptctl binary to test must be on the PATH, and the environment variable
TEST_DIR must point to a directory on a filesystem that supports encryption.

The environment variable ENABLE_VALGRIND may also be set to 1 to wrap all
invocations of fscryptctl with valgrind.

See the CONTRIBUTING.md file for more information."""

import os
import shutil
import subprocess

import pytest

# Retrieve the test directory from the environment.
RAW_TEST_DIR = os.environ.get("TEST_DIR")
if not RAW_TEST_DIR:
    raise SystemError("Need to set TEST_DIR")
if not os.path.isdir(RAW_TEST_DIR):
    raise SystemError("Directory " + RAW_TEST_DIR + " does not exist")
# Actually use a subdirectory of $TEST_DIR instead of $TEST_DIR itself, in case
# $TEST_DIR is the filesystem's root directory.  Filesystem root directories are
# nonempty (since they contain "lost+found") and can't be encrypted.
TEST_DIR = os.path.join(RAW_TEST_DIR, "test")

# Determine how the fscryptctl binary will be invoked.
FSCRYPTCTL = ["fscryptctl"]
VALGRIND_ERROR_EXITCODE = 100
if os.environ.get("ENABLE_VALGRIND") == "1":
    FSCRYPTCTL = ["valgrind", "--quiet",
                  "--error-exitcode={}".format(VALGRIND_ERROR_EXITCODE),
                  "--leak-check=full", "--errors-for-leak-kinds=all"] + FSCRYPTCTL

# The list of test keys.  The expected key identifiers were computed by
# generate_test_key_identifiers.py.

TEST_KEY = {
    "raw": (b"a" * 32) + (b"1" * 32),
    "identifier": "912ae510a458723a839a9fad701538ac",
}
TEST_KEY_32B = {
    "raw": b"abcdefghijklmnopqrstuvwxyz0123456",
    "identifier": "1c2d6754b6cc7daacb599875d7faf9bb",
}
TEST_KEY_16B = {
    "raw": b"abcdefghijklmnop",
    "identifier": "7eb80af3f24ef086726a4cea3a154ce0",
}
TEST_KEYS = [TEST_KEY, TEST_KEY_32B, TEST_KEY_16B]


def postprocess_output(output):
    """Decodes the stdout or stderr output of fscryptctl and replaces any
    references to the path of TEST_DIR with the literal string "TEST_DIR" so
    that the output is the same regardless of the location of TEST_DIR."""
    return output.decode("utf-8").strip().replace(TEST_DIR, "TEST_DIR")


def fscryptctl(*args, stdin=b"", expected_error=""):
    """Executes the fscryptctl program with the given arguments and returns the
    text (if any) that it printed to standard output.  |stdin| is the bytes to
    pass on standard input.  By default the program is expected to succeed.  If
    instead |expected_error| is nonempty, then it is expected to fail and print
    the given error message to stderr."""
    p = subprocess.Popen(FSCRYPTCTL + list(args), stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate(stdin)
    stdout = postprocess_output(stdout)
    stderr = postprocess_output(stderr)

    # Check for errors.
    if p.returncode != 0:
        assert p.returncode != VALGRIND_ERROR_EXITCODE, stderr
        if expected_error:
            assert stderr == expected_error
            return stdout
        if stderr:
            raise SystemError(stderr)
        raise subprocess.CalledProcessError(p.returncode, "fscryptctl")

    assert not stderr
    assert not expected_error
    return stdout


def list_filenames(directory):
    """Lists the filenames in the given directory."""
    filenames = []
    with os.scandir(directory) as it:
        for entry in it:
            filenames.append(entry.name)
    return filenames


def cleanup_directory():
    """Cleans up by removing the test directory and all test keys which may have
    been added to the filesystem."""
    shutil.rmtree(TEST_DIR, ignore_errors=True)
    for key in TEST_KEYS:
        try:
            fscryptctl("remove_key", key["identifier"], RAW_TEST_DIR)
        except SystemError as e:
            # It is okay if the key doesn't exist.
            assert str(e) == "error: removing key: Required key not available"


@pytest.fixture(scope="function")
def directory():
    """This fixture returns an empty unencrypted directory on a filesystem that
    supports encryption.  It also ensures that the filesystem's keyring is clear
    of any test keys."""
    # Clean up first, in case a prior invocation of the tests was killed and
    # didn't execute the pytest tear-down procedure.
    cleanup_directory()
    os.mkdir(TEST_DIR)
    yield TEST_DIR
    cleanup_directory()


def describe_policy(path=TEST_DIR, key=TEST_KEY, contents="AES-256-XTS",
                    filenames="AES-256-CTS", flags="PAD_32"):
    """Builds the expected output for a successful invocation of the get_policy
    command.  The arguments specify the settings used in the encryption policy
    as well as the path to the file or directory that has the policy."""
    path = path.replace(TEST_DIR, "TEST_DIR")
    out = "Encryption policy for {}:\n".format(path)
    out += "\tPolicy version: 2\n"
    out += "\tMaster key identifier: {}\n".format(key["identifier"])
    out += "\tContents encryption mode: {}\n".format(contents)
    out += "\tFilenames encryption mode: {}\n".format(filenames)
    out += "\tFlags: {}".format(flags)
    return out


def check_policy(path, **kwargs):
    """Runs the get_policy command on the given path and checks that its output
    matches the output produced by running describe_policy() with the given
    arguments."""
    expected_output = describe_policy(path=path, **kwargs)
    assert fscryptctl("get_policy", path) == expected_output


def prepare_encrypted_dir(directory, *set_policy_args,
                          key=TEST_KEY, expected_error=""):
    """Prepares an encrypted directory by (re-)creating the directory, adding
    the given encryption key to the appropriate keyring, and setting an
    encryption policy on the directory using the given key and encryption
    settings.  If |expected_error| is nonempty, then set_policy is expected to
    fail with the given error message."""

    # Re-create the directory, in case it already exists and is nonempty and/or
    # is already encrypted.
    shutil.rmtree(directory, ignore_errors=True)
    os.mkdir(directory)

    # Add the key to the filesystem keyring.
    key_identifier = fscryptctl("add_key", directory, stdin=key["raw"])
    assert key_identifier == key["identifier"]

    # Set the encryption policy on the directory.
    fscryptctl("set_policy", key_identifier, directory, *set_policy_args,
               expected_error=expected_error)
    if expected_error:
        return

    # Try creating a directory, a regular file, and a symlink in the encrypted
    # directory to verify that the encrypted directory seems to be working.

    subdir = os.path.join(directory, "subdir")
    os.mkdir(subdir)
    os.rmdir(subdir)

    file = os.path.join(directory, "file")
    with open(file, "w") as f:
        f.write("contents")
    with open(file, "r") as f:
        assert f.read() == "contents"
    os.remove(file)

    symlink = os.path.join(directory, "symlink")
    os.symlink("target", symlink)
    assert os.readlink(symlink) == "target"
    os.remove(symlink)


def test_help():
    """Tests that the help option is accepted."""
    fscryptctl("-h")
    fscryptctl("--help")


def test_version():
    """Tests that the version option is accepted."""
    fscryptctl("-v")
    fscryptctl("--version")


def test_unknown_command():
    """Tests that unknown commands are rejected."""
    with pytest.raises(SystemError) as e:
        fscryptctl("NONEXISTENT_COMMAND", )
    first_line = str(e.value).split("\n", 1)[0]
    assert first_line == "error: invalid command: NONEXISTENT_COMMAND"


def test_get_policy_parameters():
    """Tests that the get_policy command expects exactly one positional
    parameter."""
    for args in [[], ["foo", "bar"]]:
        fscryptctl("get_policy", *args,
                   expected_error="error: must specify a single file or directory")


def test_set_policy_parameters():
    """Tests that the set_policy command expects exactly two positional
    parameters."""
    for args in [[], ["foo"], ["foo bar baz"]]:
        fscryptctl("set_policy", *args,
                   expected_error="error: must specify a key and a directory")


def test_set_get_policy(directory):
    """Tests getting and setting an encryption policy."""
    prepare_encrypted_dir(directory)
    check_policy(directory)

    # get_policy should work on regular files too, not just directories.
    file = os.path.join(TEST_DIR, "file")
    with open(file, "w"):
        pass
    check_policy(file)

    # set_policy should succeed if the directory already has the same
    # policy, but fail if it already has a different policy.
    fscryptctl("set_policy", TEST_KEY["identifier"], directory)
    fscryptctl("set_policy", TEST_KEY_32B["identifier"], directory,
               expected_error="error: setting policy for TEST_DIR: file or directory already encrypted")


def test_get_policy_unencrypted_dir(directory):
    """Tests that the get_policy command fails on an unencrypted directory."""
    fscryptctl("get_policy", directory,
               expected_error="error: getting policy for TEST_DIR: file or directory not encrypted")


def test_get_policy_nonexistent_dir():
    """Tests that the get_policy command fails on a nonexistent directory."""
    fscryptctl("get_policy", "NONEXISTENT",
               expected_error="error: opening NONEXISTENT: No such file or directory")


def test_set_policy_nonexistent_dir():
    """Tests that the set_policy command fails on a nonexistent directory."""
    fscryptctl("set_policy", TEST_KEY["identifier"], "NONEXISTENT",
               expected_error="error: opening NONEXISTENT: No such file or directory")


def test_set_policy_nonempty_dir(directory):
    """Tests that the set_policy command fails on a nonempty directory."""
    os.mkdir(os.path.join(directory, "subdir"))
    fscryptctl("set_policy", TEST_KEY["identifier"], directory,
               expected_error="error: setting policy for TEST_DIR: Directory not empty")


def test_filename_like_option(directory):
    """Tests that fscryptctl can operate on filenames that look like options."""
    orig_cwd = os.getcwd()
    try:
        os.chdir(directory)
        fscryptctl("add_key", ".", stdin=TEST_KEY["raw"])
        for subdir in ["-h", "-v", "--help", "--version"]:
            os.mkdir(subdir)
            fscryptctl("set_policy", TEST_KEY["identifier"], "--", subdir)
            expected_output = describe_policy(path=subdir)
            assert fscryptctl("get_policy", "--", subdir) == expected_output
    finally:
        os.chdir(orig_cwd)


def test_set_get_policy_alternate_padding(directory):
    """Tests getting and setting an encryption policy with a non-default value
    for the filenames padding option."""
    for padding in [4, 8, 16, 32]:
        prepare_encrypted_dir(directory, "--padding={}".format(padding))
        check_policy(directory, flags="PAD_{}".format(padding))


def test_set_get_policy_aes_256_xts(directory):
    """Tests getting and setting an encryption policy that uses AES-256-XTS
    contents encryption and AES-256-CTS filenames encryption.  (Note that this
    is also the default setting, but this test tries it explicitly.)"""
    prepare_encrypted_dir(directory, "--contents=AES-256-XTS",
                          "--filenames=AES-256-CTS")
    check_policy(directory, contents="AES-256-XTS", filenames="AES-256-CTS")
    # AES-256-XTS is only allowed with master keys that are 32 bytes or longer.
    # Shorter keys shouldn't work.
    for key in [TEST_KEY_16B]:
        with pytest.raises(OSError):
            prepare_encrypted_dir(directory, "--contents=AES-256-XTS",
                                  "--filenames=AES-256-CTS", key=key)


def test_set_get_policy_aes_128_cbc(directory):
    """Tests getting and setting an encryption policy that uses AES-128-CBC
    contents encryption and AES-128-CTS filenames encryption."""

    # This algorithm isn't guaranteed to be available, so skip this test if the
    # kernel lacks the crypto API support that is needed to run it.
    try:
        prepare_encrypted_dir(directory, "--contents=AES-128-CBC",
                              "--filenames=AES-128-CTS")
    except OSError as e:
        assert "Package not installed" in str(e)
        pytest.skip("Kernel doesn't support AES-128-CBC encryption")

    # AES-128-CBC expects a key that is 16 bytes or longer.
    for key in [TEST_KEY_16B, TEST_KEY_32B, TEST_KEY]:
        prepare_encrypted_dir(directory, "--contents=AES-128-CBC",
                              "--filenames=AES-128-CTS", key=key)
        check_policy(directory, key=key, contents="AES-128-CBC",
                     filenames="AES-128-CTS")


def test_set_get_policy_adiantum(directory):
    """Tests getting and setting an encryption policy that uses Adiantum
    encryption."""

    # This algorithm isn't guaranteed to be available, so skip this test if the
    # kernel lacks the crypto API support that is needed to run it.
    try:
        prepare_encrypted_dir(directory, "--contents=Adiantum",
                              "--filenames=Adiantum")
    except OSError as e:
        assert "Package not installed" in str(e)
        pytest.skip("Kernel doesn't support Adiantum encryption")

    # The --direct-key flag is allowed with Adiantum.
    for direct_key in [False, True]:
        for padding in [4, 16, 32, None]:
            set_policy_args = ["--contents=Adiantum", "--filenames=Adiantum"]

            # The padding and direct_key options both go in the flags field
            # of the encryption policy, so make sure that one (or both) of
            # them doesn't accidentally overwrite the other.
            if padding and padding == 4:
                set_policy_args.append("--padding={}".format(padding))
            if direct_key:
                set_policy_args.append("--direct-key")
            if padding and padding != 4:
                set_policy_args.append("--padding={}".format(padding))

            if padding:
                flags = "PAD_{}".format(padding)
            else:
                flags = "PAD_32"
            if direct_key:
                flags += ", DIRECT_KEY"

            # Adiantum expects a key that is 32 bytes or longer.
            for key in [TEST_KEY_32B, TEST_KEY]:
                prepare_encrypted_dir(directory, *set_policy_args, key=key)
                check_policy(directory, key=key, contents="Adiantum",
                             filenames="Adiantum", flags=flags)
            with pytest.raises(OSError):
                prepare_encrypted_dir(directory, "--contents=Adiantum",
                                      "--filenames=Adiantum", key=TEST_KEY_16B)


def test_set_get_policy_aes_256_hctr2(directory):
    """Tests getting and setting an encryption policy that uses AES-256-HCTR2
    filenames encryption.  Note that the kernel doesn't yet support
    AES-256-HCTR2 contents encryption, so that is not tested."""

    # Skip the test if the kernel lacks support for AES-256-HCTR2.
    try:
        prepare_encrypted_dir(directory, "--contents=AES-256-XTS",
                              "--filenames=AES-256-HCTR2")
    except SystemError as e:
        # Old kernel that doesn't know about AES-256-HCTR2
        assert "invalid encryption options provided" in str(e)
        pytest.skip("Kernel doesn't support AES-256-HCTR2 encryption")
    except OSError as e:
        # New kernel that knows about AES-256-HCTR2, but doesn't have HCTR2
        # support enabled in the crypto API.
        assert "Package not installed" in str(e)
        pytest.skip("Kernel doesn't support AES-256-HCTR2 encryption")

    for padding in [4, 16, 32, None]:
        set_policy_args = ["--contents=AES-256-XTS", "--filenames=AES-256-HCTR2"]
        if padding:
            set_policy_args.append("--padding={}".format(padding))
            flags = "PAD_{}".format(padding)
        else:
            flags = "PAD_32"

        for key in [TEST_KEY_32B, TEST_KEY]:
            prepare_encrypted_dir(directory, *set_policy_args, key=key)
            check_policy(directory, key=key, contents="AES-256-XTS",
                         filenames="AES-256-HCTR2", flags=flags)


def test_set_get_policy_iv_ino_lblk_64(directory):
    """Tests getting and setting an encryption policy that uses the
    IV_INO_LBLK_64 flag."""
    # This flag may not always be accepted, as on some filesystems it is only
    # allowed if the filesystem was formatted with '-O stable_inodes'.
    try:
        prepare_encrypted_dir(directory, "--iv-ino-lblk-64")
    except SystemError as e:
        assert "invalid encryption options provided" in str(e)


def test_set_get_policy_iv_ino_lblk_32(directory):
    """Tests getting and setting an encryption policy that uses the
    IV_INO_LBLK_32 flag."""
    # This flag may not always be accepted, as on some filesystems it is only
    # allowed if the filesystem was formatted with '-O stable_inodes'.
    try:
        prepare_encrypted_dir(directory, "--iv-ino-lblk-32")
    except SystemError as e:
        assert "invalid encryption options provided" in str(e)


def test_set_policy_bad_padding(directory):
    """Tests that the set_policy command rejects unrecognized padding flags."""
    prepare_encrypted_dir(directory, "--padding=0",
                          expected_error="error: invalid padding: 0")


def test_set_policy_bad_mode(directory):
    """Tests that the set_policy command rejects unrecognized encryption
    modes."""
    for mode_type in ["contents", "filenames"]:
        prepare_encrypted_dir(directory, "--{}=foo".format(mode_type),
                              expected_error="error: invalid {} mode: foo".format(mode_type))


def test_set_policy_bad_mode_combination(directory):
    """ Tests setting and using an encryption policy with a combination of
    encryption modes that isn't supported by the kernel."""
    # AES-256 must be paired with AES-128.
    prepare_encrypted_dir(directory, "--contents=AES-256-XTS",
                          "--filenames=AES-128-CTS",
                          expected_error="error: setting policy for TEST_DIR: invalid encryption options provided")


def test_set_policy_bad_key(directory):
    """Tests that the set_policy command expects a valid key identifier."""
    fscryptctl("set_policy", "bad", directory,
               expected_error="error: invalid key identifier: bad")
    fscryptctl("set_policy", "X" * 32, directory,
               expected_error="error: invalid key identifier: " + "X" * 32)


def test_key_status_parameters():
    """Tests that the key_status command expects exactly two positional
    parameters."""
    for args in [[], ["foo"], ["foo", "bar", "baz"]]:
        fscryptctl("key_status", *args,
                   expected_error="error: must specify a key identifier and a mountpoint")


def test_key_status_needs_key_identifier(directory):
    """Tests that the key_status command expects a valid key identifier."""
    fscryptctl("key_status", "bad", directory,
               expected_error="error: invalid key identifier: bad")


def test_key_status_needs_directory():
    """Tests that the key_status command expects an existing directory."""
    fscryptctl("key_status", TEST_KEY["identifier"], "NONEXISTENT",
               expected_error="error: opening NONEXISTENT: No such file or directory")


def check_key_status(key, directory, status):
    """Helper function which checks that the given key has the given status on
    the filesystem that contains the given directory."""
    assert fscryptctl("key_status", key["identifier"], directory) == status


def check_key_present(key, directory):
    """Helper function which checks that the given key is present on the
    filesystem that contains the given directory."""
    check_key_status(key, directory, "Present (user_count=1, added_by_self)")


def check_key_absent(key, directory):
    """Helper function which checks that the given key is absent from the
    filesystem that contains the given directory."""
    check_key_status(key, directory, "Absent")


def check_key_incompletely_removed(key, directory):
    """Helper function which checks that the given key is incompletely removed
    from the filesystem that contains the given directory."""
    check_key_status(key, directory, "Incompletely removed")


def test_add_key_parameters():
    """Tests that the add_key command expects exactly one positional
    parameter."""
    for args in [[], ["foo", "bar"]]:
        fscryptctl("add_key", *args,
                   expected_error="error: must specify a single mountpoint")


def test_add_key_validates_keysize(directory):
    """Tests that the add_key command expects a key with a valid size."""
    for keysize in range(16):
        fscryptctl("add_key", directory, stdin=b"X" * keysize,
                   expected_error="error: key was too short; it must be at least 16 bytes")
    fscryptctl("add_key", directory, stdin=b"X" * 65,
               expected_error="error: key was too long; it can be at most 64 bytes")


def test_add_key_needs_directory():
    """Tests that the add_key command expects an existing directory."""
    fscryptctl("add_key", "NONEXISTENT", stdin=TEST_KEY["raw"],
               expected_error="error: opening NONEXISTENT: No such file or directory")


def test_add_key(directory):
    """Tests adding some encryption keys and getting their statuses."""
    for key in TEST_KEYS:
        check_key_absent(key, directory)
        assert fscryptctl("add_key", directory,
                          stdin=key["raw"]) == key["identifier"]
        check_key_present(key, directory)


def test_remove_key_parameters():
    """Tests that the remove_key command expects exactly two positional
    parameters."""
    for args in [[], ["foo"], ["foo", "bar", "baz"]]:
        fscryptctl("remove_key", *args,
                   expected_error="error: must specify a key identifier and a mountpoint")


def test_remove_key_needs_key_identifier(directory):
    """Tests that the remove_key command expects a valid key identifier."""
    fscryptctl("remove_key", "bad", directory,
               expected_error="error: invalid key identifier: bad")


def test_remove_key_needs_key(directory):
    """Tests that the remove_key command expects an existing key."""
    fscryptctl("remove_key", b"0" * 32, directory,
               expected_error="error: removing key: Required key not available")


def test_remove_key_needs_directory():
    """Tests that the remove_key command expects an existing directory."""
    fscryptctl("remove_key", TEST_KEY["identifier"], "NONEXISTENT",
               expected_error="error: opening NONEXISTENT: No such file or directory")


def test_remove_key(directory):
    """Tests adding and removing some encryption keys, and getting their
    statuses."""
    for key in TEST_KEYS:
        check_key_absent(key, directory)
        identifier = fscryptctl("add_key", directory, stdin=key["raw"])
        check_key_present(key, directory)
        assert fscryptctl("remove_key", identifier, directory) == ""
        check_key_absent(key, directory)


def test_remove_key_incomplete(directory):
    """Tests removing an encryption key when files using it are still in-use."""

    prepare_encrypted_dir(directory)
    file = os.path.join(directory, "file")

    # Do add_key/remove_key/key_status on the parent directory so that these
    # commands don't interfere with the test by causing the key to be in-use
    # when the command opens the path it is given.
    parent_dir = os.path.join(directory, "..")

    check_key_present(TEST_KEY, parent_dir)
    with open(file, "w"):
        for _ in range(3):
            # Since a file in the directory is still open, remove_key should
            # print a warning and transition the key to the "Incompletely
            # removed" state, not the "Absent" state.
            expected_output = "warning: some files using this key are still in-use"
            assert fscryptctl(
                "remove_key", TEST_KEY["identifier"], parent_dir) == expected_output
            check_key_incompletely_removed(TEST_KEY, parent_dir)

    # Now that the directory is no longer in-use, remove_key should succeed
    # and transition the key to the "Absent" state.
    assert fscryptctl("remove_key", TEST_KEY["identifier"], parent_dir) == ""
    check_key_absent(TEST_KEY, parent_dir)


def test_remove_key_locks_files(directory):
    """Tests that remove_key really "locks" access to files in an encrypted
    directory, and that add_key restores access again."""
    parent_dir = os.path.join(directory, "..")

    # Create an encrypted directory.
    prepare_encrypted_dir(directory)

    # Create a regular file in the encrypted directory.
    filename = "file"
    file_path = os.path.join(directory, filename)
    with open(file_path, "w") as f:
        f.write("contents")

    # Remove the directory's encryption key.
    fscryptctl("remove_key", TEST_KEY["identifier"], parent_dir)

    # The filenames should now be listed as no-key names.
    nokey_filenames = list_filenames(directory)
    assert len(nokey_filenames) == 1
    nokey_path = os.path.join(directory, nokey_filenames[0])
    assert nokey_filenames[0] != filename
    with pytest.raises(FileNotFoundError):
        open(file_path, "r")

    # Opening a file via no-key name should fail.
    with pytest.raises(OSError) as e:
        open(nokey_path)
    assert "Required key not available" in str(e.value)

    # Adding the key should restore access to the file.
    fscryptctl("add_key", parent_dir, stdin=TEST_KEY["raw"])
    with open(file_path, "r") as f:
        assert f.read() == "contents"
    with pytest.raises(FileNotFoundError):
        open(nokey_path, "r")
    assert list_filenames(directory) == [filename]
