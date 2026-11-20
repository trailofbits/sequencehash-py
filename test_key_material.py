"""
Tests for how SequenceMAC handles the caller's key (best-effort zeroization).

Run with: python -m unittest test_key_material
"""

import hashlib
import unittest
import warnings

import sequencehash


# CCTV SequenceMAC vectors (SHA-256): a 32-byte key, and a key longer than
# the block size, which is hashed down first.
VECTORS = [
    (
        "89f2b36cb4713fa72f593d75e2122e47be4921e1cd9bc6a4f87e631c6d0f01bb",
        "544553545f7368613235365f39366561393439305f676f6f64",
        "be59876dcbff85bd662e272b9c2ecd7527d902fe9bd6db26f56dd01bfec46d5d",
    ),
    (
        "524db8fcfd86c6dbf4baf613a4d60d05a3c97c913682d40268746f34e5ffac78"
        "a37496df806d9bc29515ef8ac8927d3ff5ea062c2843651961feb7b427d8e9c7"
        "dc0df67ccf5c",
        "544553545f7368613235365f38396133306330615f77656972645f6b6579",
        "f4bd925a1ada4ca77ce40894fa064debd19d5aa2525cbfbd39a0adb0a7a3fe81",
    ),
]


class RecordingSHA256:
    """A PEP 247 hash module that records every value passed to update()."""

    calls = []

    def __init__(self):
        self._h = hashlib.sha256()
        self.digest_size = self._h.digest_size
        self.block_size = self._h.block_size
        self.name = self._h.name

    @classmethod
    def new(cls):
        return cls()

    def update(self, data):
        RecordingSHA256.calls.append(data)
        self._h.update(data)

    def copy(self):
        other = RecordingSHA256.__new__(RecordingSHA256)
        other._h = self._h.copy()
        other.digest_size = self.digest_size
        other.block_size = self.block_size
        other.name = self.name
        return other

    def digest(self):
        return self._h.digest()


def mac(key, digestmod="sha256"):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return sequencehash.SequenceMAC.new(key, digestmod=digestmod)


class TestKeyMaterial(unittest.TestCase):

    def test_vectors_with_any_bytes_like_key(self):
        for key_hex, cust_hex, expected in VECTORS:
            key = bytes.fromhex(key_hex)
            cust = bytes.fromhex(cust_hex)
            for wrap in (bytes, bytearray, memoryview):
                with self.subTest(key_len=len(key), key_type=wrap.__name__):
                    out = mac(wrap(key)).result_with_customizer(cust)
                    self.assertEqual(out.hex(), expected)

    def test_callers_key_is_unchanged_and_not_held(self):
        for key_hex, cust_hex, expected in VECTORS:
            key = bytearray.fromhex(key_hex)
            before = bytes(key)
            m = mac(key)
            self.assertEqual(bytes(key), before)
            # A bytearray can't be resized while a memoryview of it is
            # alive, so this raises BufferError if the MAC kept a view of
            # the key. The caller can then wipe it.
            key.extend(b"\x00")
            del key[-1]
            key[:] = b"\x00" * len(key)
            # The MAC still works after the caller wiped the key.
            out = m.result_with_customizer(bytes.fromhex(cust_hex))
            self.assertEqual(out.hex(), expected)

    def test_key_is_not_copied_into_bytes(self):
        # The key, minus its tweaked first byte, must reach the hash objects
        # as a view of the caller's key, never as a new bytes copy.
        key = bytes.fromhex(VECTORS[0][0])
        RecordingSHA256.calls = []
        mac(key, digestmod=RecordingSHA256)
        rest = key[1:]
        views = [c for c in RecordingSHA256.calls if bytes(c) == rest]
        self.assertEqual(len(views), 2)  # inner and outer hash
        for c in views:
            self.assertIsInstance(c, memoryview)


if __name__ == "__main__":
    unittest.main()
