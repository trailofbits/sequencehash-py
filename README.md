# ElementMAC and ElementHash for Python

This library provides the `ElementHash` and `ElementMAC` constructions, which are hash-based constructions used for computing hashes and MACs of structured data. This can be useful, for instance, when computing MACs for complex data structures, or when computing Fiat-Shamir challenges over a large number of inputs.

The goal is simple: keep programmers from accidentally feeding data into hash functions in an ambiguous (and therefore dangerous) way.

# How to Use It

The APIs for `ElementHash` and `ElementMAC` strive to be drop-in replacements for the `hashlib` and `hmac` modules.

To create a new `ElementHash` object with `sha512` as the underlying hash function:

```py
hasher = elementhash.ElementHash.new('sha512')
```

For `ElementMAC`, you'll need to supply a key as well:

```py
my_key = b'\x00' * 32
hasher = elementhash.ElementMAC.new(mykey, digestmod='sha512')
```

`ElementHash` and `ElementMAC` also have the advantage of including domain separators. If you need to use the hash or MAC of a value in multiple contexts, you can simply provide a different `separator` argument for each:

```py
hasher1 = elementhash.ElementHash.new(digestmod='sha512', separator=b'FUNCTION_ONE')
hasher2 = elementhash.ElementHash.new(digestmod='sha512', separator=b'FUNCTION_TWO')
mac1 = elementhash.ElementMAC.new(digestmod='sha512', key=b'\x00' * 64, separator=b'FUNCTION_ONE')
mac2 = elementhash.ElementMAC.new(digestmod='sha512', key=b'\x00' * 64, separator=b'FUNCTION_TWO')
```

Once you've created your hashing and MAC objects, they act just like any other hash or MAC object, with the exception that each input will be a separate, encoded value. That means that updating an `ElementHash` object with `ab`, then `cd` will NOT give you the same result as updating it `abcd` or `a` and `bcd`.