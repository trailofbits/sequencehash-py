# SequenceMAC and SequenceHash for Python

This library provides the `SequenceHash` and `SequenceMAC` constructions, which are hash-based constructions used for computing hashes and MACs of semantically-separated pieces of data. This can be useful, for instance, when computing MACs for complex data structures, or when computing Fiat-Shamir challenges over a large number of inputs.

The goal is simple: keep programmers from accidentally feeding data into hash functions in an ambiguous (and therefore dangerous) way.

## Short and insecure hashes

SequenceHash and SequenceMAC are only as secure as the underlying hash function. A "short hash" has less than 32 bytes of output (for example SHA-1, MD5, SHA-224 or SHA3-224). With a short hash, SequenceHash gives less than 128-bit collision resistance, and SequenceMAC's security is bounded by the output length no matter how long the key is. MD4, MD5 and SHA-1 also have known cryptanalytic attacks. Prefer a hash with at least 32 bytes of output, such as SHA-256 or SHA-512.

The [specification](https://c2sp.org/sequencehash) lets implementations either warn about or reject short hashes. This library allows them and emits a `sequencehash.WeakHashWarning` (a `UserWarning`) when one is used. If you need a short hash, for example to interoperate with an existing system, filter that warning:

```py
import os
import warnings

import sequencehash

with warnings.catch_warnings():
    warnings.simplefilter('ignore', sequencehash.WeakHashWarning)
    hasher = sequencehash.SequenceMAC.new(os.urandom(32), digestmod='sha1')
```

# How to Use It

The APIs for `SequenceHash` and `SequenceMAC` strive to be nearly drop-in replacements for the `hashlib` and `hmac` modules.

To create a new `SequenceHash` object with `sha512` as the underlying hash function:

```py
hasher = sequencehash.SequenceHash.new('sha512')
```

For `SequenceMAC`, you'll need to supply a key as well:

```py
my_key = b'\x00' * 32
hasher = sequencehash.SequenceMAC.new(mykey, digestmod='sha512')
```

To incorporate a new value into the hash, simply use the `add` method:

```py
my_key = b'\x00' * 32
hasher = sequencehash.SequenceMAC.new(mykey, digestmod='sha512')
hasher.add(b'Test')
```

You can call `add` an arbitrary number of times (up to `2 ** 128 - 1` times, technically). When you're done, simply call `result` for an uncustomized hash or MAC:


```py
my_key = b'\x00' * 32
hasher = sequencehash.SequenceMAC.new(mykey, digestmod='sha512')
hasher.add(b'Test')
print(hasher.result().hex())
```

If you wish to incorporate a customization string (for instance, to prevent cross-domain replay in a protocol), you can simply call `result_with_customizer`:

```py
my_key = b'\x00' * 32
hasher = sequencehash.SequenceMAC.new(mykey, digestmod='sha512')
hasher.add(b'Test')
print(hasher.result_with_customizer(b'PROTOCOL_ROUND_000').hex())
```