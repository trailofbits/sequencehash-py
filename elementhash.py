#!/usr/bin/env python3

from typing import Any, Optional, Union

import hashlib

# Initialization string
INITIALIZER_INNER: bytes = b'ELTHSH_I'
INITIALIZER_OUTER: bytes = b'ELTHSH_O'

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


def derive_block(value: bytes, algo: str) -> bytes:
    """
    Processes a byte string according to the HMAC key derivation algorithm: if
    the byte string is shorter than or equal to the block length of the given
    hash algorithm, it is padded with zeroes to the block length. If it is
    longer than the block length, it is hashed with the given algorithm, and
    the result is zero-padded out to the block length of the hash algorithm.
    """
    hsh = hashlib.new(algo)
    if len(value) > hsh.block_size:
        hsh.update(value)
        value = hsh.digest()
    value = pad(value, hsh.block_size)
    return value


def new(digestmod: str,
        key: Optional[bytes]=None,
        separator: Optional[bytes]=None) -> Union["ElementHash", "ElementMAC"]:
    """
    Returns a new `ElementHash` object with the underlying hash function given
    by `digestmod`, optionally including the domain separation value
    `separator`.

    If a `key` value is specified, returns an `ElementMAC` object with the
    underlying hash function and key, optionally including the domain
    separation value `separator`.
    """
    if key is not None:
        return ElementMAC(digestmod=digestmod, key=key, separator=separator)
    return newHash(digestmod, separator=separator)


def newHash(digestmod: str, separator: Optional[bytes]=None) -> "ElementHash":
    return ElementHash(digestmod, sep=separator)


def newMAC(digestmod: str, key: bytes, separator: Optional[bytes]=None)\
    -> "ElementHash":
    return ElementMAC(digestmod, key=key, sep=separator)


class ElementMAC:
    """
    A hash-agnostic MAC algorithm that avoids ambiguous encoding issues.
    """
    finished:       bool        # Tracks when the hash has been finalized
    hasher:         Any         # "Internal" hash value
    finalizer:      Any         # Provides the final hash value
    item_count:     int         # Tracks the total number of items hashed
    algo_name:      str         # hashlib selector
    digest_size:    int         # Size of the hash output
    block_size:     int         # Block size for the hash

    def __init__(self,
                 key: bytes,
                 msg: Optional[bytes]=None,
                 digestmod: Optional[str]=None,
                 separator: Optional[bytes]=None):
        """
        Creates a new ElementMAC object using the selected hash algorithm and
        key
        """
        if digestmod is None:
            raise ValueError("Unspecified hash algorithm")

        self.finished = False
        self.algo_name = digestmod
        self.item_count = 0
        self.hasher = hashlib.new(digestmod)
        self.finalizer = hashlib.new(digestmod)
        if self.hasher.block_size <= 24:
            raise ValueError("Specified hash has invalid block size")
        self.digest_size = self.hasher.digest_size
        self.block_size = self.hasher.block_size

        self.__hash_init(key, separator)

        if msg is not None:
            self.update(msg)
        return


    def __hash_init(self, key: bytes, sep: Optional[bytes]):
        if sep is None:
            sep = b''
        derived_key = derive_block(key, self.algo_name)
        derived_sep = derive_block(sep, self.algo_name)
        key_len_bytes = encode_int_msbf(len(key))
        sep_len_bytes = encode_int_msbf(len(sep))

        # Initialize the inner hasher
        inner_block: bytes = pad(INITIALIZER_INNER + key_len_bytes,
                                 self.block_size)
        self.hasher.update(inner_block)
        self.hasher.update(derived_key)

        # Initialize the outer hasher
        outer_block: bytes = pad(
            INITIALIZER_OUTER + sep_len_bytes + key_len_bytes, self.block_size)
        self.finalizer.update(outer_block)
        self.finalizer.update(derived_sep)
        self.finalizer.update(derived_key)
        return


    def __finalize(self) -> None:
        item_bytes: bytes = encode_int_msbf(self.item_count)
        out_len_bytes: bytes = encode_int_msbf(self.digest_size)
        self.finalizer.update(item_bytes)
        self.finalizer.update(out_len_bytes)
        self.finalizer.update(self.hasher.digest())
        self.finished = True
        return


    def copy(self) -> "ElementMAC":
        """
        Creates a new ElementMAC object with the same internal state.
        """
        new_hasher = ElementMAC(b'', None, self.algo_name)
        new_hasher.item_count = self.item_count
        new_hasher.finished = self.finished
        new_hasher.hasher = self.hasher.copy()
        new_hasher.finalizer = self.finalizer.copy()
        return new_hasher


    def update(self, data: bytes):
        """
        Incorporates a new byte string into the MAC. Note that this an atomic
        operation: each input is length-encoded before being integrated into
        the underlying hash, so adding `b'\x00\x01\x02\x03'` is NOT the same as
        adding `b'\x00\x01'` and `b'\x02\x03'` in sequence.
        """
        if self.finished:
            raise RuntimeError("Cannot update  hash that has already completed")
        if self.item_count >= MAX_ITEMS:
            raise RuntimeError("Too many objects hashed")

        data_encoded: bytes = encode_data_little(data)
        self.hasher.update(data_encoded)
        self.item_count += 1
        return


    def digest(self) -> bytes:
        """
        Returns the final hash of the objects as a byte string
        """
        if not self.finished:
            self.__finalize()

        return self.finalizer.digest()


    def hexdigest(self) -> str:
        """
        Returns the final hash of the objects as a hex string
        """
        digest = self.digest()
        return digest.hex()


class ElementHash:
    """
    A hash-agnostic MAC algorithm that avoids ambiguous encoding issues.
    """
    elementMAC: ElementMAC

    def __init__(self, digestmod: str, sep: Optional[bytes]=None):
        if sep is None:
            sep = b''
        self.elementMAC = ElementMAC(key=b'',
                                     separator=sep, msg=None,
                                     digestmod=digestmod)
        return

    def copy(self) -> "ElementHash":
        new_mac = self.elementMAC.copy()
        new_hash = ElementHash(self.elementMAC.algo_name)
        new_hash.elementMAC = new_mac
        return new_hash

    def digest(self) -> bytes:
        return self.elementMAC.digest()

    def hexdigest(self) -> str:
        return self.elementMAC.hexdigest()

    def update(self, msg: bytes):
        self.elementMAC.update(msg)
