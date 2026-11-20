import unittest
import warnings

import sequencehash

# Every fixed-output hash in hashlib.algorithms_guaranteed, including the
# short and insecure ones that the library allows with a warning.
HASHES = [
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
    "blake2b",
    "blake2s",
]

KEY = bytes(range(1, 65))  # Non-zero, and long enough for every hash above


def new(kind, digestmod):
    """Creates a SequenceMAC or SequenceHash without the expected warnings."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        if kind == "mac":
            return sequencehash.SequenceMAC.new(KEY, digestmod=digestmod)
        return sequencehash.SequenceHash.new(digestmod)


def fresh(kind, digestmod, *items):
    """Creates a new object and adds `items` to it."""
    obj = new(kind, digestmod)
    for item in items:
        obj.add(item)
    return obj


CASES = [(kind, digestmod) for kind in ("mac", "hash") for digestmod in HASHES]


class TestCopy(unittest.TestCase):
    def test_copy_short_hash_mac(self):
        # Reproduction from the issue: this raised "Key length too short".
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            m = sequencehash.SequenceMAC.new(b"\x01" * 32, digestmod="sha1")
        m.add(b"x")
        self.assertEqual(m.copy().result(), m.result())

    def test_copy_has_same_state(self):
        for kind, digestmod in CASES:
            with self.subTest(kind=kind, digestmod=digestmod):
                original = fresh(kind, digestmod, b"a", b"")
                c = original.copy()
                self.assertEqual(c.result(), original.result())
                self.assertEqual(
                    c.result_with_customizer(b"cust"),
                    original.result_with_customizer(b"cust"),
                )
                original.add(b"b")
                c.add(b"b")
                expected = fresh(kind, digestmod, b"a", b"", b"b")
                self.assertEqual(c.result(), expected.result())
                self.assertEqual(original.result(), expected.result())

    def test_copy_is_independent(self):
        for kind, digestmod in CASES:
            with self.subTest(kind=kind, digestmod=digestmod):
                original = fresh(kind, digestmod, b"a")
                c = original.copy()
                c.add(b"only in copy")
                original.add(b"only in original")
                self.assertEqual(
                    c.result(), fresh(kind, digestmod, b"a", b"only in copy").result()
                )
                self.assertEqual(
                    original.result(),
                    fresh(kind, digestmod, b"a", b"only in original").result(),
                )

    def test_copy_keeps_initial_state_for_reset(self):
        for kind, digestmod in CASES:
            with self.subTest(kind=kind, digestmod=digestmod):
                original = fresh(kind, digestmod, b"a")
                c = original.copy()
                c.reset()
                c.add(b"z")
                self.assertEqual(c.result(), fresh(kind, digestmod, b"z").result())
                # Resetting the copy doesn't touch the original.
                self.assertEqual(
                    original.result(), fresh(kind, digestmod, b"a").result()
                )

    def test_copy_emits_no_warnings(self):
        for kind, digestmod in CASES:
            with self.subTest(kind=kind, digestmod=digestmod):
                original = fresh(kind, digestmod, b"a")
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    original.copy()
                self.assertEqual([str(w.message) for w in caught], [])


if __name__ == "__main__":
    unittest.main()
