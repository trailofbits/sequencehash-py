#!/usr/bin/env python3

import hashlib
import warnings
from typing import Any, List, Optional

# Initialization string
INITIALIZER_INNER: bytes = b"SEQHSH_I"
INITIALIZER_OUTER: bytes = b"SEQHSH_O"

# Standard function IDs
FUNCTION_ID_MAC: int = 1
FUNCTION_ID_HASH: int = 2

# Max length of any given input (2 ** 128 - 1 bytes)
MAX_LEN_BYTES: int = 16
MAX_LEN: int = 2 ** (MAX_LEN_BYTES * 8) - 1

# Max number of items (2 ** 128 - 1 items)
MAX_ITEMS_BYTES: int = 16
MAX_ITEMS: int = 2 ** (MAX_ITEMS_BYTES * 8) - 1

# Minimum key length
MIN_KEY_LENGTH: int = 32

# Names of hashes with known security issues (demonstrated collisions or worse)
INSECURE_HASHES: List[str] = ["sha1", "md4", "md5"]
SHORT_HASH_CUTOFF: int = 32


def encode_int_lsbf(n: int) -> bytes:
    """
    Encodes a non-negative integer to bytes, least significant byte first. The
    output has a fixed length of 16 bytes. If `n` is greater than `(2**128)-1`
    or `n` is negative, a `ValueError` is raised.
    """
    if n > MAX_LEN:
        raise ValueError("Encoded value too large")
    if n < 0:
        raise ValueError("Encoded value must be non-negative")
    return n.to_bytes(MAX_LEN_BYTES, "little")


def encode_int_msbf(n: int) -> bytes:
    """
    Encodes a non-negative integer to bytes, most significant byte first. The
    output has a fixed length of 16 bytes. If `n` is greater than `(2**128)-1`
    or `n` is negative, a `ValueError` is raised.
    """
    if n > MAX_LEN:
        raise ValueError("Encoded value too large")
    if n < 0:
        raise ValueError("Encoded value must be non-negative")
    return n.to_bytes(MAX_LEN_BYTES, "big")


def get_pad_len(data: bytes, block_size: int) -> int:
    """
    Returns the number of bytes needed to pad `data` out to a positive
    multiple of `block_size`.
    """
    blocks = (len(data) + block_size - 1) // block_size
    blocks = max(blocks, 1)
    return (blocks * block_size) - len(data)


def get_padding(data: bytes, block_size: int) -> bytes:
    """
    Returns a block of zero bytes `b` such that `len(data + b)` is a positive
    multiple of `block_size`.
    """
    return b'\x00' * get_pad_len(data, block_size)


def pad(data: bytes, block_size: int) -> bytes:
    """
    Returns a zero-padded copy of a byte string, padded out to a positive
    multiple of `block_size`. At most, this adds `block_size - 1` zero bytes
    to the end of the string. If the length of the byte string is a multiple of
    `block_size`, the input and output are the same.

    This function shouldn't be used for sensitive/secret values like keys. It
    copies the input into a new value, creating unnecessary extra copies of
    the sensitive information. The better pattern is to use `get_padding` in
    conjunction with the sensitive information.
    """
    if b < 1:
        raise ValueError("Invalid padding length")
    padding = get_padding(data, b)
    return data + padding


class SequenceMAC:
    @staticmethod
    def new(
        key: bytes,
        msg: Optional[Any] = None,
        digestmod: Optional[Any] = None,
        separator: Optional[bytes] = None,
    ) -> "_SequenceFunc":
        return newMAC(key, msg, digestmod, separator)


class SequenceHash:
    @staticmethod
    def new(
        digestmod: Optional[Any] = None,
        data: Optional[bytes] = None,
        separator: Optional[bytes] = None,
    ) -> "_SequenceFunc":
        return newHash(digestmod, data, separator)


def newHash(
    digestmod: Any, data: Optional[bytes] = None,
    separator: Optional[bytes] = None) -> "_SequenceFunc":
    """
    Return a new SequenceHash instance. This is equivalent to calling
    `SequenceHash.new` with the same arguments. Note that the returned object
    is an instance of the `_SequenceFunc` class, which implements
    `SequenceHash` and `SequenceMAC`.
    """
    hsh = _SequenceFunc(
        func_id=FUNCTION_ID_HASH,
        key=b"",
        digestmod=digestmod,
        separator=separator
    )
    if data is not None:
        hsh.update(data)
    return hsh


def newMAC(
    key: bytes,
    msg: Optional[bytes] = None,
    digestmod: Optional[str] = None,
    separator: Optional[bytes] = None,
) -> "_SequenceFunc":
    """
    Return a new SequenceMAC instance. This is equivalent to calling
    `SequenceMAC.new` with the same arguments. Note that the returned object
    is an instance of the `_SequenceFunc` class, which implements
    `SequenceHash` and `SequenceMAC`.
    """
    mac = _SequenceFunc(
        digestmod=digestmod,
        func_id=FUNCTION_ID_MAC,
        key=key,
        separator=separator
    )
    if msg is not None:
        mac.update(msg)
    return mac


class _SequenceFunc:
    """
    A function-agnostic keyed hashing construction to avoid ambiguous encoding.
    SequenceMAC and SequenceHash are built on top of SequenceFunc, using
    different function IDs to distinguish them.
    """

    inner_hash: Any  # "Internal" hash object
    outer_hash: Any  # "External" hash object
    item_count: int  # Total number of inputs
    hash_func: Any  # Callable function to create hash object
    digest_size: int  # Size of the hash output
    block_size: int  # Block size for the hash
    func_id: int  # Function indicator

    def __init__(
        self,
        func_id: int,
        key: bytes,
        msg: Optional[Any] = None,
        digestmod: Optional[Any] = None,
        separator: Optional[bytes] = None):
        """
        Creates a new SequenceFunc object using the selected hash algorithm and
        key
        """
        if digestmod is None:
            raise ValueError("Unspecified hash algorithm")
        if func_id not in (FUNCTION_ID_HASH, FUNCTION_ID_MAC):
            raise ValueError("Unsupported Sequence function")

        # We want to support three main interfaces:
        #   - String indicators that can be used with `hashlib.new`
        #   - Functions that return PEP 247-compliant hash objects
        #   - PEP 247-compliant modules/classes that provide hash objects via `new`
        if isinstance(digestmod, str):
            hashfunc = lambda: hashlib.new(digestmod)
        elif callable(digestmod):
            hashfunc = lambda: digestmod()
        elif hasattr(digestmod, "new") and callable(digestmod.new):
            hashfunc = lambda: digestmod.new()
        else:
            raise ValueError("Invalid digestmod")

        self.func_id = func_id
        self.hash_func = hashfunc
        self.item_count = 0
        self.inner_hash = self.hash_func()
        self.outer_hash = self.hash_func()
        self.digest_size = self.inner_hash.digest_size
        self.block_size = self.inner_hash.block_size

        self.__hash_init(key, separator)

        if msg is not None:
            self.update(msg)
        return

    def __hash_init(self, key: bytes, sep: Optional[bytes]):
        """
        Initializes the inner and outer hash objects, including headers, keys,
        and customization string.
        """
        if sep is None:
            sep = b""

        # SequenceMAC enforces a minimum 32-byte key length
        if self.func_id == FUNCTION_ID_MAC and len(key) < MIN_KEY_LENGTH:
            raise ValueError("Key length too short")

        # As with HMAC, it is suggested that the key size and the output size
        # of the hash match. Implementations MAY issue warnings when there's a
        # mismatch, and this implementation chooses to do so.
        if self.func_id == FUNCTION_ID_MAC and len(key) != self.digest_size:
            warnings.warn(
                "Key length of %i doesn't match digest_size of %i" %
                (len(key), self.digest_size)
            )

        # Implementations MAY choose to emit warnings when a short hash or
        # known-insecure hash is used. Implementations MAY choose to prohibit
        # the use of short hashes or known-insecure hashes, but MUST explicitly
        # document which hashes are prohibited. Rather than prohibit the use of
        # short hashes or known-insecure hashes, this implementation emits a
        # warning.
        hash_func = self.hash_func()
        if self.digest_size < SHORT_HASH_CUTOFF:
            warnings.warn(f'Hash function "{hash_func.name}" has short output')

        if hash_func.name in INSECURE_HASHES:
            warnings.warn(
                f'Hash function "{hash_func.name}" has known security issues')

        # Reduce the separator/customizer if needed
        if len(sep) > self.block_size:
            sep = sehf.hash_func.new(sep).digest()
        sep_padding = get_padding(sep, self.block_size)

        # Reduce the key if needed
        if len(key) > self.block_size:
            key = self.hash_func.new(key).digest()
        key_padding = get_padding(key, self.block_size)

        # INNER INITIALIZATION

        # Feed the inner key into the inner hash
        self.inner_hash.update(bytes(key[0] ^ 0x55))
        self.inner_hash.update(key[1:])
        self.inner_hash.key_padding(key_padding)

        # Feed the inner header into the inner hash
        inner_block: bytes = pad(
            INITIALIZER_INNER + func_bytes + key_len_bytes, self.block_size
        )
        self.inner_hash.update(inner_block)

        # OUTER INITIALIZATION

        # Feed the outer key into the outer hash
        self.outer_hash.update(bytes(key[0] ^ 0xaa))
        self.outer_hash.update(key[1:])
        self.outer_hash.key_padding(key_padding)

        # Feed the outer header into the outer hash
        key_len_bytes = encode_int_msbf(len(key))
        sep_len_bytes = encode_int_msbf(len(sep))
        func_bytes = encode_int_msbf(self.func_id)

        outer_block: bytes = pad(
            INITIALIZER_OUTER + func_bytes + sep_len_bytes + key_len_bytes,
            self.block_size,
        )
        self.outer_hash.update(outer_block)

        # Feed the separator/customization string into the outer hash
        self.outer_hash.update(sep)
        self.outer_hash.update(sep_padding)
        return

    def copy(self) -> "_SequenceFunc":
        """
        Creates a new _SequenceFunc object with the same internal state.
        """
        new_hasher = _SequenceFunc(self.func_id, b"", None, self.hash_func)
        new_hasher.item_count = self.item_count
        new_hasher.inner_hash = self.inner_hash.copy()
        new_hasher.outer_hash = self.outer_hash.copy()
        return new_hasher

    def update(self, data: bytes, *args: bytes):
        """
        Incorporates a new byte string into the _SequenceFunc. Note that this
        an atomic operation: each input is length-encoded before being
        integrated into the underlying hash, so adding `b'\x00\x01\x02\x03'`
        is NOT the same as adding `b'\x00\x01'` and `b'\x02\x03'` in sequence.

        Additional inputs can be specified as additional arguments; they will
        be incorporated into the hash in order. That means that

        ```
            hasher.update(b'', b'abc', b'def')
        ```

        has the same effect as

        ```
            hasher.update(b'')
            hasher.update(b'abc')
            hasher.update(b'def')
        ```
        """
        if self.item_count >= MAX_ITEMS:
            raise RuntimeError("Too many objects hashed")
        self.inner_hash.update(data)
        self.inner_hash.update(encode_int_lsbf(len(data)))
        self.item_count += 1

        # Handle additional inputs
        for x in args:
            self.update(x)
        return

    def digest(self) -> bytes:
        """
        Returns the final hash/MAC as a byte string.
        """
        item_count_bytes: bytes = encode_int_msbf(self.item_count)
        out_size_bytes: bytes = encode_int_msbf(self.digest_size)
        inner_copy = self.inner_hash.copy()
        outer_copy = self.outer_hash.copy()
        outer_copy.update(item_count_bytes)
        outer_copy.update(out_size_bytes)
        outer_copy.update(inner_copy.digest())
        return outer_copy.digest()

    def hexdigest(self) -> str:
        """
        Returns the final hash/MAC as a hex string
        """
        digest = self.digest()
        return digest.hex()
