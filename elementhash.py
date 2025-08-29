#!/usr/bin/env python3

from typing import Any, Optional

import hashlib

# Initialization string
INITIALIZER_INNER: bytes = b'ELTHSH_I'
INITIALIZER_OUTER: bytes = b'ELTHSH_O'

# Standard function IDs
FUNCTION_ID_MAC: int = 1
FUNCTION_ID_HASH: int = 2

# Max length of any given input (2 ** 128 - 1 bytes)
MAX_LEN_BYTES: int = 16
MAX_LEN: int = 2 ** (MAX_LEN_BYTES * 8) - 1

# Max number of items (2 ** 128 - 1 items)
MAX_ITEMS_BYTES: int = 16
MAX_ITEMS: int = 2 ** (MAX_ITEMS_BYTES * 8) - 1


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
    return n.to_bytes(MAX_LEN_BYTES, 'little')


def encode_data_little(data: bytes) -> bytes:
    """
    Encodes a byte string by prepending its length as a 128-bit integer
    """
    encoded_len: bytes = encode_int_lsbf(len(data))
    return encoded_len + data


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
    return n.to_bytes(MAX_LEN_BYTES, 'big')


def pad(data: bytes, b: int) -> bytes:
    """
    Returns a zero-padded copy of a byte string, padded out to the next
    multiple of the block size `b`. At most, this adds `b - 1` zero bytes to
    the end of the string. If the length of the byte string is a multiple of
    `b`, the input and output are the same.
    """
    blocks: int = max(1, (len(data) + b - 1) // b)
    padded_length: int = blocks * b
    pad_len = padded_length - len(data)
    padding = b'\x00' * pad_len
    padded = data + padding
    return padded


def derive_block(value: bytes, algo: Any) -> bytes:
    """
    Processes a byte string according to the HMAC key derivation algorithm: if
    the byte string is shorter than or equal to the block length of the given
    hash algorithm, it is padded with zeroes to the block length. If it is
    longer than the block length, it is hashed with the given algorithm, and
    the result is zero-padded out to the block length of the hash algorithm.
    """
    hsh = algo()
    if len(value) > hsh.block_size:
        hsh.update(value)
        value = hsh.digest()
    value = pad(value, hsh.block_size)
    return value


class ElementMAC:
    @staticmethod
    def new(
            key: bytes,
            msg: Optional[Any]=None,
            digestmod: Optional[str]=None,
            separator: Optional[bytes]=None) -> "_ElementFunc":
        return newMAC(key, msg, digestmod, separator)

class ElementHash:
    @staticmethod
    def new(
            digestmod: Optional[Any]=None,
            data: Optional[bytes]=None,
            separator: Optional[bytes]=None) -> "_ElementFunc":
        return newHash(digestmod, data, separator)


def newHash(
        digestmod: Any,
        data: Optional[bytes]=None,
        separator: Optional[bytes]=None) -> "_ElementFunc":
    """
    Return a new ElementHash instance
    """
    hsh = _ElementFunc(func_id=FUNCTION_ID_HASH,
                       key=b'',
                       digestmod=digestmod,
                       separator=separator)
    if data is not None:
        hsh.update(data)
    return hsh


def newMAC(
        key: bytes,
        msg: Optional[bytes]=None,
        digestmod: Optional[str]=None,
        separator: Optional[bytes]=None) -> "_ElementFunc":
    """
    Return a new ElementMAC instance
    """
    mac = _ElementFunc(digestmod=digestmod,
                       func_id=FUNCTION_ID_MAC,
                       key=key,
                       separator=separator)
    if msg is not None:
        mac.update(msg)
    return mac


class _ElementFunc:
    """
    A function-agnostic keyed hashing construction to avoid ambiguous encoding.
    ElementMAC and ElementHash are built on top of ElementFunc, using different
    function IDs to distinguish them.
    """
    inner_hash:     Any         # "Internal" hash object
    outer_hash:     Any         # "External" hash object
    item_count:     int         # Total number of inputs
    hash_func:      Any         # Callable function to create hash object
    digest_size:    int         # Size of the hash output
    block_size:     int         # Block size for the hash
    func_id:        int         # Function indicator

    def __init__(self,
                 func_id: int,
                 key: bytes,
                 msg: Optional[Any]=None,
                 digestmod: Optional[Any]=None,
                 separator: Optional[bytes]=None):
        """
        Creates a new ElementMAC object using the selected hash algorithm and
        key
        """
        if digestmod is None:
            raise ValueError("Unspecified hash algorithm")
        if func_id not in (FUNCTION_ID_HASH, FUNCTION_ID_MAC):
            raise ValueError("Unsupported Element function")

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
        self.inner_hash = self.hash_func() #hashlib.new(digestmod)
        self.outer_hash = self.hash_func() # hashlib.new(digestmod)
        self.digest_size = self.inner_hash.digest_size
        self.block_size = self.inner_hash.block_size

        self.__hash_init(key, separator)

        if msg is not None:
            self.update(msg)
        return


    def __hash_init(self, key: bytes, sep: Optional[bytes]):
        if sep is None:
            sep = b''
        derived_key = derive_block(key, self.hash_func)
        derived_sep = derive_block(sep, self.hash_func)
        key_len_bytes = encode_int_msbf(len(key))
        sep_len_bytes = encode_int_msbf(len(sep))
        func_bytes = encode_int_msbf(self.func_id)

        # Initialize the inner hasher
        inner_block: bytes = pad(INITIALIZER_INNER + func_bytes +
                                 key_len_bytes, self.block_size)
        self.inner_hash.update(inner_block)
        self.inner_hash.update(derived_key)

        # Initialize the outer hasher
        outer_block: bytes = pad(INITIALIZER_OUTER + func_bytes +
                                 sep_len_bytes + key_len_bytes,
                                 self.block_size)
        self.outer_hash.update(outer_block)
        self.outer_hash.update(derived_sep)
        self.outer_hash.update(derived_key)
        return


    def copy(self) -> "_ElementFunc":
        """
        Creates a new ElementMAC object with the same internal state.
        """
        new_hasher = _ElementFunc(self.func_id, b'', None, self.hash_func)
        new_hasher.item_count = self.item_count
        new_hasher.inner_hash = self.inner_hash.copy()
        new_hasher.outer_hash = self.outer_hash.copy()
        return new_hasher
    

    def update(self, data: bytes):
        """
        Incorporates a new byte string into the MAC. Note that this an atomic
        operation: each input is length-encoded before being integrated into
        the underlying hash, so adding `b'\x00\x01\x02\x03'` is NOT the same as
        adding `b'\x00\x01'` and `b'\x02\x03'` in sequence.
        """
        if self.item_count >= MAX_ITEMS:
            raise RuntimeError("Too many objects hashed")

        data_encoded: bytes = encode_data_little(data)
        self.inner_hash.update(data_encoded)
        self.item_count += 1
        return


    def digest(self) -> bytes:
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
        Returns the final hash of the objects as a hex string
        """
        digest = self.digest()
        return digest.hex()