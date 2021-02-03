#
# Copyright 2020 Google LLC
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

"""This program generates the key descriptors and key identifiers for the test
keys in test.py."""

import hashlib
import test

# For HKDF-SHA512; see
# https://www.pycryptodome.org/en/latest/src/protocol/kdf.html#hkdf
import Crypto.Hash.SHA512
import Crypto.Protocol.KDF


def compute_key_descriptor(raw):
    return hashlib.sha512(hashlib.sha512(raw).digest()).hexdigest()[:16]


def compute_key_identifier(raw):
    return Crypto.Protocol.KDF.HKDF(raw, 16, "", Crypto.Hash.SHA512,
                                    context=b"fscrypt\0\1").hex()


for key in test.TEST_KEYS:
    raw = key["raw"]
    descriptor = compute_key_descriptor(raw)
    identifier = compute_key_identifier(raw)
    if "descriptor" in key:
        assert descriptor == key["descriptor"]
    if "identifier" in key:
        assert identifier == key["identifier"]
    print("... = {")
    print("    raw: " + str(raw) + ",")
    print('    "descriptor": "' + descriptor + '",')
    print('    "identifier": "' + identifier + '",')
    print("}")
