#!/usr/bin/env python3

import hashlib
from pathlib import Path
from typing import List, NamedTuple, Tuple

import pytest

import elementhash

HASH_ALGO: str = 'sha256'
HASH_FUNC = lambda: hashlib.new(HASH_ALGO)
BLOCK_LEN: int = HASH_FUNC().block_size
OUT_LEN: int = HASH_FUNC().digest_size

# DEFAULT_TEST_KEY = SHA256("Trail of Bits")
DEFAULT_TEST_KEY: bytes = bytes.fromhex(\
    "65506e9ec54e98568f2288ce7f9fcc41719ec17e89d95d7b120749a9c5701c5a")

class ElementTestVector(NamedTuple):
    base_hash:      str
    expected_out:   str
    expected_inner: str
    key:            str
    separator:      str
    test_inputs:    List[str]
    raw_inner:      List[str]
    raw_outer:      List[str]


class TestSupports:
    def test_encode_int_lsbf(self):
        # Check byte ordering with 1
        assert(elementhash.encode_int_lsbf(1) == b'\x01' + b'\x00' * 15)
        # Check byte ordering with 2 ** 127
        assert(elementhash.encode_int_lsbf(2 ** 127) == b'\x00' * 15 + b'\x80')

        # Check that a value that's too large results in an exception
        with pytest.raises(ValueError):
            elementhash.encode_int_lsbf(2 ** 128)

        # Check that a negative value results in an exception
        with pytest.raises(ValueError):
            elementhash.encode_int_lsbf(-1)
        return


    def test_encode_int_msbf(self):
        # Check byte ordering with 1
        assert(elementhash.encode_int_msbf(1) == b'\x00' * 15 + b'\x01')
        # Check byte ordering with 2 ** 127
        assert(elementhash.encode_int_msbf(2 ** 127) == b'\x80' + b'\x00' * 15)

        # Check that a value that's too large results in an exception
        with pytest.raises(ValueError):
            elementhash.encode_int_msbf(2 ** 128)

        # Check that a negative value results in an exception
        with pytest.raises(ValueError):
            elementhash.encode_int_msbf(-1)
        return


    def test_encode_data_little(self):
        LEN: int = 32
        DATA: bytes = b'\xff' * LEN
        encoded_data = elementhash.encode_data_little(DATA)
        assert(encoded_data == elementhash.encode_int_lsbf(LEN) + DATA)

        # Check length of an empty string encoding
        encoded_data = elementhash.encode_data_little(b'')
        assert(len(encoded_data) == len(elementhash.encode_int_lsbf(0)))
        return


    def test_pad(self):
        PAD_LEN: int = 64

        # Verify that padded values of different lengths come back padded to a
        # POSITIVE multiple of the pad length
        for l in range(0, PAD_LEN * 3):
            data: bytes = b'\x00' * l
            padded: bytes = elementhash.pad(data, PAD_LEN)

            # Assert that the padded length is a multiple of the padding length
            assert(len(padded) % PAD_LEN == 0)

            # Assert that the padded length is NOT zero
            assert(len(padded) != 0)

            # Make sure that the first `l` bytes match the data
            assert(padded[:l] == data)

            # Make sure that the last bytes are all 0
            pad_len: int = len(padded) - len(data)
            assert(padded[l:] == b'\x00' * pad_len)
        
        # Make sure that we can't specify an invalid padding length
        with pytest.raises(ValueError):
            elementhash.pad(b'\x00' * 32, 0)
        return


    def test_derive_block(self):
        # Verify that we get back thes same size result for all our inputs
        for l in range(0, HASH_FUNC().block_size * 2):
            key = b'\x00' * l
            derived = elementhash.derive_block(key, HASH_FUNC)

            # Check that our output is of the expected size
            assert(len(derived) == BLOCK_LEN)

            # Check to see if the key material matches our expected value
            if l <= BLOCK_LEN:
                assert(key == derived[:l])
            else:
                hasher = HASH_FUNC()
                hasher.update(key)
                key_hash: bytes = hasher.digest()
                assert(key_hash == derived[:OUT_LEN])
        return
    
class TestHashAPI:
    def test_new(self):
        # Test that we can get a valid hash from a valid string specifier
        hasher = elementhash.ElementHash.new('sha256')

        # Test that we can get a valid hash from a function returning a hash
        hasher = elementhash.ElementHash.new(HASH_FUNC)

        # Test that we can get a valid hash from a PEP-247 namespace
        hasher = elementhash.ElementHash.new(hashlib.sha256)

        # Test that we _can't_ get a valid hash from invalid specifiers
        with pytest.raises(ValueError):
            hasher = elementhash.ElementHash.new("not_a_hash")
        return


    def test_new_with_separator(self):
        SEPARATOR0: bytes = b'SEPARATOR 0000'

        # Test that we can get a valid hash from a valid string specifier
        hasher = elementhash.ElementHash.new('sha256', separator=SEPARATOR0)

        # Test that we can get a valid hash from a function returning a hash
        hasher = elementhash.ElementHash.new(HASH_FUNC, separator=SEPARATOR0)

        # Test that we can get a valid hash from a PEP-247 namespace
        hasher = elementhash.ElementHash.new(hashlib.sha256,
                                             separator=SEPARATOR0)
        return


    def test_update(self):
        INPUT: bytes = b'abcdef'
        HEX_EXPECTED: str  =\
            "be3fd59ab122461d3ddf2bff6f41f8b4508912cfc483c6374c7790edff4a7ebd"
        hasher = elementhash.ElementHash.new(HASH_FUNC)
        hasher.update(INPUT)
        assert(hasher.hexdigest() == HEX_EXPECTED)
        return


    def test_update_multi(self):
        INPUTS: Tuple[bytes, ...]= (b'abc', b'', b'def')
        HEX_EXPECTED: str =\
            "a7edb4e3c7f33e12e66b244b5a6effd5656abcbf0fb25f73112d542d197420e0"
        hasher = elementhash.ElementHash.new(HASH_FUNC)
        hasher.update(*INPUTS)
        assert(hasher.hexdigest() == HEX_EXPECTED)
        return


    def test_separators(self):
        SEPARATOR0: bytes = b'SEPARATOR 0000'
        SEPARATOR1: bytes = b'SEPARATOR 0001'

        hasher0 = elementhash.ElementHash.new(HASH_FUNC, separator=SEPARATOR0)
        hasher1 = elementhash.ElementHash.new(HASH_FUNC, separator=SEPARATOR1)

        hasher0.update(b'\x00' * 32)
        hasher1.update(b'\x00' * 32)
        hasher0.update(b'')
        hasher1.update(b'')

        assert(hasher0.hexdigest() != hasher1.hexdigest())
        return


    def test_copy(self):
        hasher0 = elementhash.ElementHash.new(HASH_FUNC)
        hasher0.update(b'\x00')
        hasher0.update(b'\x01')
        hasher0.update(b'\x02')
        hasher1 = hasher0.copy()
        hasher0.update(b'\x03')
        hasher1.update(b'\x03')
        assert(hasher0.hexdigest() == hasher1.hexdigest())
        return


class TestMACAPI:
    def test_new(self):
        # Test that we can get a valid hash from a valid string specifier
        hasher = elementhash.ElementMAC.new(key=DEFAULT_TEST_KEY,
                                            digestmod='sha256')

        # Test that we can get a valid hash from a function returning a hash
        hasher = elementhash.ElementMAC.new(key=DEFAULT_TEST_KEY,
                                            digestmod=HASH_FUNC)

        # Test that we can get a valid hash from a PEP-247 namespace
        hasher = elementhash.ElementMAC.new(key=DEFAULT_TEST_KEY,
                                            digestmod=hashlib.sha256)

        # Test that we _can't_ get a valid hash from invalid specifiers
        with pytest.raises(ValueError):
            hasher = elementhash.ElementMAC.new(key=DEFAULT_TEST_KEY,
                                                digestmod="not_a_hash")
        return


    def test_new_with_separator(self):
        SEPARATOR0: bytes = b'SEPARATOR 0000'

        # Test that we can get a valid hash from a valid string specifier
        hasher = elementhash.ElementMAC.new(key=DEFAULT_TEST_KEY,
                                            digestmod='sha256',
                                            separator=SEPARATOR0)

        # Test that we can get a valid hash from a function returning a hash
        hasher = elementhash.ElementMAC.new(key=DEFAULT_TEST_KEY,
                                            digestmod=HASH_FUNC,
                                            separator=SEPARATOR0)

        # Test that we can get a valid hash from a PEP-247 namespace
        hasher = elementhash.ElementMAC.new(key=DEFAULT_TEST_KEY,
                                            digestmod=hashlib.sha256,
                                            separator=SEPARATOR0)
        return


    def test_update(self):
        INPUT: bytes = b'abcdef'
        HEX_EXPECTED: str  =\
            "f45b5a17e91b992d6d695c9986a2f4b6288331e225c0c5121279b741312d023c"
        hasher = elementhash.ElementMAC.new(key=DEFAULT_TEST_KEY,
                                            digestmod=HASH_FUNC)
        hasher.update(INPUT)
        assert(hasher.hexdigest() == HEX_EXPECTED)
        return


    def test_update_multi(self):
        INPUTS: Tuple[bytes, ...]= (b'abc', b'', b'def')
        HEX_EXPECTED: str =\
            "105b03464a3a384d386272c5c89f93ea70ce79bceb59c5cc24e59cafa030cd09"
        hasher = elementhash.ElementMAC.new(key=DEFAULT_TEST_KEY,
                                            digestmod=HASH_FUNC)
        hasher.update(*INPUTS)
        assert(hasher.hexdigest() == HEX_EXPECTED)
        return


    def test_separators(self):
        SEPARATOR0: bytes = b'SEPARATOR 0000'
        SEPARATOR1: bytes = b'SEPARATOR 0001'

        hasher0 = elementhash.ElementMAC.new(key=DEFAULT_TEST_KEY,
                                             digestmod=HASH_FUNC,
                                             separator=SEPARATOR0)
        hasher1 = elementhash.ElementMAC.new(key=DEFAULT_TEST_KEY,
                                             digestmod=HASH_FUNC,
                                             separator=SEPARATOR1)

        hasher0.update(b'\x00' * 32, b'', b'\xff' * 32)
        hasher1.update(b'\x00' * 32, b'', b'\xff' * 32)

        assert(hasher0.hexdigest() != hasher1.hexdigest())
        return


    def test_copy(self):
        # Create a MAC object
        hasher0 = elementhash.ElementMAC.new(key=DEFAULT_TEST_KEY,
                                             digestmod=HASH_FUNC)
        
        # Write to it
        hasher0.update(b'\x00')
        hasher0.update(b'\x01')
        hasher0.update(b'\x02')

        # Clone it
        hasher1 = hasher0.copy()

        # Write the same data to both
        hasher0.update(b'\x03')
        hasher1.update(b'\x03')

        # Verify that they both give the same output
        assert(hasher0.hexdigest() == hasher1.hexdigest())
        return


def validate_MAC_vector(vec: ElementTestVector):
    key = bytes.fromhex(vec.key)
    sep = bytes.fromhex(vec.separator)
    inputs = [bytes.fromhex(x) for x in vec.test_inputs]
    mac = elementhash.ElementMAC.new(key=key, separator=sep,
                                     digestmod=vec.base_hash)
    for inpt in inputs:
        mac.update(inpt)
    assert(mac.hexdigest() == vec.expected_out)
    return


def validate_hash_vector(vec: ElementTestVector):
    sep = bytes.fromhex(vec.separator)
    inputs = [bytes.fromhex(x) for x in vec.test_inputs]
    hasher = elementhash.ElementHash.new(separator=sep,
                                         digestmod=vec.base_hash)
    for inpt in inputs:
        hasher.update(inpt)
    assert(hasher.hexdigest() == vec.expected_out)
    return


def load_vectors(path: Path):
    import json
    vector_file = open(path, "r")
    vec_list = json.load(vector_file)
    vectors = [ElementTestVector(**x) for x in vec_list["tests"]]
    return vectors


def run_hash_file(path: Path):
    vectors = load_vectors(path)
    for v in vectors:
        validate_hash_vector(v)
    return


def run_mac_file(path: Path):
    vectors = load_vectors(path)
    for v in vectors:
        validate_MAC_vector(v)
    return


def test_hash_vectors():
    """
    Validates implementation against the ElementHash test vectors files
    """
    base_file_name = "vectors_hash_"
    base_file_extension = ".json"
    algo_names = ["ripemd160", "sha1", "sha256", "sha3_256", "sha3_384", "sha3_512", "sha384", "sha512"]
    base_path: Path = Path("testvectors")
    for algo in algo_names:
        filename  = base_file_name + algo + base_file_extension
        path = base_path / Path(filename)
        run_hash_file(path)

def test_mac_vectors():
    """
    Validates implementation against the ElementMAC test vectors files
    """
    base_file_name = "vectors_mac_"
    base_file_extension = ".json"
    algo_names = ["ripemd160", "sha1", "sha256", "sha3_256", "sha3_384", "sha3_512", "sha384", "sha512"]
    base_path: Path = Path("testvectors")
    for algo in algo_names:
        filename  = base_file_name + algo + base_file_extension
        path = base_path / Path(filename)
        run_mac_file(path)