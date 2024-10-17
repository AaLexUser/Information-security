import pytest
from src.pcbc import PCBC
from src.idea import IDEA

@pytest.fixture
def valid_key():
    return b'16bytekeyforIDEA'

@pytest.fixture
def invalid_key():
    return b'short_key'

@pytest.fixture
def cipher(valid_key):
    return IDEA(valid_key)

@pytest.fixture
def pcbc(cipher):
    return PCBC(cipher)

def test_idea_key_length_valid(valid_key):
    """Test initializing IDEA with a valid key length."""
    try:
        idea = IDEA(valid_key)
    except ValueError:
        pytest.fail("IDEA raised ValueError unexpectedly with a valid key length.")

def test_idea_key_length_invalid(invalid_key):
    """Test initializing IDEA with an invalid key length."""
    with pytest.raises(ValueError) as exc_info:
        IDEA(invalid_key)
    assert "Key must be 16 bytes long" in str(exc_info.value)

def test_addition(cipher: IDEA):
    """Test the addition operation."""
    assert cipher.add(0x1234, 0x0001) == 0x1235
    assert cipher.add(0xFFFF, 0x0001) == 0x0000  # Overflow

def test_subtraction(cipher: IDEA):
    """Test the additive inverse operation."""
    assert cipher.add_inv(0x1234) == 0xEDCC
    assert cipher.add_inv(0x0000) == 0x0000
    assert cipher.add_inv(0xFFFF) == 0x0001


def test_generate_round_keys(cipher: IDEA):
    """Test round key generation."""
    assert len(cipher.round_keys) == 52
    # Additional checks can be added based on known key schedule

def test_encrypt_decrypt(pcbc: PCBC):
    """Test that encryption followed by decryption returns the original plaintext."""
    plaintext = b'This is a test message for IDEA-PCBC mode.'
    iv = b'\x00' * 8
    ciphertext = pcbc.encrypt(plaintext, iv)
    decrypted = pcbc.decrypt(ciphertext, iv)
    assert decrypted == plaintext

def test_padding(pcbc: PCBC):
    """Test padding and unpadding operations."""
    data = b'Y' * 10
    padded = pcbc.pad(data)
    assert len(padded) == 16  # 10 + 6 padding bytes
    assert padded.endswith(b'\x06' * 6)
    unpadded = pcbc.unpad(padded)
    assert unpadded == data

def test_unpad_invalid(pcbc: PCBC):
    """Test unpadding with invalid padding."""
    invalid_padded = b'Y' * 10 + b'\x09'
    with pytest.raises(ValueError) as exc_info:
        pcbc.unpad(invalid_padded)
    assert "Invalid padding" in str(exc_info.value)

def test_decrypt_invalid_block_size(pcbc: PCBC):
    """Test decryption with invalid ciphertext block size."""
    with pytest.raises(ValueError) as exc_info:
        pcbc.decrypt(b'1234567', b'\x00' * 8)  # 7 bytes instead of 8
    assert "Ciphertext length must be multiple of 8 bytes" in str(exc_info.value)

def test_encrypt_decrypt_empty(pcbc: PCBC):
    """Test encryption and decryption of an empty plaintext."""
    plaintext = b''
    iv = b'\x00' * 8
    ciphertext = pcbc.encrypt(plaintext, iv)
    decrypted = pcbc.decrypt(ciphertext, iv)
    assert decrypted == plaintext

def test_encrypt_decrypt_large_data(pcbc: PCBC):
    """Test encryption and decryption of large data."""
    plaintext = b'A' * 1024  # 1 KB of data
    iv = b'\x00' * 8
    ciphertext = pcbc.encrypt(plaintext, iv)
    decrypted = pcbc.decrypt(ciphertext, iv)
    assert decrypted == plaintext