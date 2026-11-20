import unittest
import warnings

import sequencehash

KEY = bytes(range(1, 65))

# (hashlib name, expected WeakHashWarning messages)
WEAK = {
    "md5": ["has short output", "has known security issues"],
    "sha1": ["has short output", "has known security issues"],
    "sha224": ["has short output"],
    "sha3_224": ["has short output"],
}
STRONG = ["sha256", "sha384", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"]


def constructors(digestmod):
    # Key length equals digest size, so the separate key length warning
    # doesn't fire.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        size = sequencehash.SequenceHash.new(digestmod).digest_size
    key = KEY[: max(size, 32)]
    return {
        "mac": lambda: sequencehash.SequenceMAC.new(key, digestmod=digestmod),
        "hash": lambda: sequencehash.SequenceHash.new(digestmod),
    }


def caught(make):
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        make()
    return w


class TestWeakHashWarning(unittest.TestCase):
    def test_weak_hashes_warn(self):
        for digestmod, expected in WEAK.items():
            for kind, make in constructors(digestmod).items():
                with self.subTest(kind=kind, digestmod=digestmod):
                    w = caught(make)
                    self.assertEqual(
                        [x.category for x in w],
                        [sequencehash.WeakHashWarning] * len(expected),
                    )
                    for msg, x in zip(expected, w):
                        self.assertIn(msg, str(x.message))

    def test_strong_hashes_do_not_warn(self):
        for digestmod in STRONG:
            for kind, make in constructors(digestmod).items():
                with self.subTest(kind=kind, digestmod=digestmod):
                    self.assertEqual(caught(make), [])

    def test_key_length_warning_unchanged_for_other_hashes(self):
        w = caught(lambda: sequencehash.SequenceMAC.new(KEY[:32], digestmod="sha512"))
        self.assertEqual(
            [str(x.message) for x in w],
            ["Key length of 32 doesn't match digest_size of 64"],
        )
        self.assertEqual(
            caught(lambda: sequencehash.SequenceMAC.new(KEY[:64], digestmod="sha512")),
            [],
        )

    def test_warning_is_a_user_warning(self):
        self.assertTrue(issubclass(sequencehash.WeakHashWarning, UserWarning))

    def test_filtering_the_category_opts_in(self):
        # The README's opt-in. A short hash can't match the 32-byte minimum
        # key length, so no key length warning is emitted either.
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            warnings.simplefilter("ignore", sequencehash.WeakHashWarning)
            mac = sequencehash.SequenceMAC.new(KEY[:32], digestmod="sha1")
        self.assertEqual([str(x.message) for x in w], [])
        mac.add(b"x")
        self.assertEqual(len(mac.result()), 20)


if __name__ == "__main__":
    unittest.main()
