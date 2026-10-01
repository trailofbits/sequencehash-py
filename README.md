# SequenceMAC and SequenceHash for Python

This library provides the `SequenceHash` and `SequenceMAC` constructions, which are hash-based constructions used for computing hashes and MACs of semantically-separated pieces of data. This can be useful, for instance, when computing MACs for complex data structures, or when computing Fiat-Shamir challenges over a large number of inputs.

The goal is simple: keep programmers from accidentally feeding data into hash functions in an ambiguous (and therefore dangerous) way.

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