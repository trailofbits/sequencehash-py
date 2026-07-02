# SequenceMAC and SequenceHash for Python

This library provides the `SequenceHash` and `SequenceMAC` constructions, which are hash-based constructions used for computing hashes and MACs of semantically-separated pieces of data. This can be useful, for instance, when computing MACs for complex data structures, or when computing Fiat-Shamir challenges over a large number of inputs.

The goal is simple: keep programmers from accidentally feeding data into hash functions in an ambiguous (and therefore dangerous) way.

# How to Use It

The APIs for `SequenceHash` and `SequenceMAC` strive to be drop-in replacements for the `hashlib` and `hmac` modules.

To create a new `SequenceHash` object with `sha512` as the underlying hash function:

```py
hasher = sequencehash.SequenceHash.new('sha512')
```

For `SequenceMAC`, you'll need to supply a key as well:

```py
my_key = b'\x00' * 32
hasher = sequencehash.SequenceMAC.new(mykey, digestmod='sha512')
```

`SequenceHash` and `SequenceMAC` also have the advantage of including domain separators. If you need to use the hash or MAC of a value in multiple contexts, you can simply provide a different `separator` argument for each:

```py
hasher1 = sequencehash.SequenceHash.new(digestmod='sha512', separator=b'FUNCTION_ONE')
hasher2 = sequencehash.SequenceHash.new(digestmod='sha512', separator=b'FUNCTION_TWO')
mac1 = sequencehash.SequenceMAC.new(digestmod='sha512', key=b'\x00' * 64, separator=b'FUNCTION_ONE')
mac2 = sequencehash.SequenceMAC.new(digestmod='sha512', key=b'\x00' * 64, separator=b'FUNCTION_TWO')
```

Once you've created your hashing and MAC objects, they act just like any other hash or MAC object, with the exception that each input will be a separate, encoded value. That means that updating an `SequenceHash` object with `ab`, then `cd` will NOT give you the same result as updating it `abcd` or `a` and `bcd`.
