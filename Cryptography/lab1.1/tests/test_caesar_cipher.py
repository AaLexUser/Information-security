import pytest
from src.caesar_cipher import CaesarCipher

@pytest.fixture
def cipher():
    return CaesarCipher(3)

def test_encrypt_english_lower(cipher):
    assert cipher.encrypt('abcxyz') == 'defabc'

def test_decrypt_english_lower(cipher):
    assert cipher.decrypt('defabc') == 'abcxyz'

def test_encrypt_english_upper(cipher):
    assert cipher.encrypt('ABCXYZ') == 'DEFABC'

def test_decrypt_english_upper(cipher):
    assert cipher.decrypt('DEFABC') == 'ABCXYZ'

def test_encrypt_russian_lower():
    cipher = CaesarCipher(5)
    assert cipher.encrypt('абвяюя') == 'еёждгд'

def test_decrypt_russian_lower():
    cipher = CaesarCipher(5)
    assert cipher.decrypt('еёждгд') == 'абвяюя'

def test_encrypt_mixed(cipher):
    assert cipher.encrypt('Hello Привет') == 'Khoor Тулезх'

def test_decrypt_mixed(cipher):
    assert cipher.decrypt('Khoor Тулезх') == 'Hello Привет'

def test_shift_wraparound_english(cipher):
    assert cipher.encrypt('xyzXYZ') == 'abcABC'

def test_shift_wraparound_russian():
    cipher = CaesarCipher(33)  # Shift equal to Russian alphabet length
    original = 'привет'
    encrypted = cipher.encrypt(original)
    assert encrypted == original  # Full shift should return original

def test_non_alphabetic(cipher):
    assert cipher.encrypt('123!@# abc') == '123!@# def'

def test_empty_string(cipher):
    assert cipher.encrypt('') == ''
    assert cipher.decrypt('') == ''

def test_large_shift():
    large_shift = 100
    effective_shift = large_shift % 26
    assert CaesarCipher(large_shift).encrypt('abc') == CaesarCipher(effective_shift).encrypt('abc')