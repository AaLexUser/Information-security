# Лабораторная работа №2: Блочное симметричное шифрование

## Название и цель работы

**Название:**  
Блочное симметричное шифрование: Реализация алгоритма IDEA в режиме PCBC.

**Цель работы:**  
Изучение структуры и основных принципов работы современных алгоритмов блочного симметричного шифрования. Приобретение навыков программной реализации блочных симметричных шифров, конкретно алгоритма IDEA в режиме PCBC.

## Задание

Реализовать систему симметричного блочного шифрования, позволяющую шифровать и дешифровать файл на диске с использованием алгоритма IDEA в режиме PCBC.

## Вариант задания

2в. 

| Алгоритм | Режим шифрования |
|----------|-------------------|
| IDEA     | PCBC              |

## Структура проекта

```shell
Cryptography/
└── lab1.2/
    ├── src/
    │   ├── idea.py
    │   ├── pcbc.py
    │   └── main.py
    ├── input.txt
    ├── encrypted.bin
    ├── decrypted.txt
    └── tests/
        ├── test_idea_pcbc_cipher.py
```

## Описание файлов

### Описание основных компонентов

#### `main.py`

Основной файл для шифрования и дешифровки файлов. Предоставляет интерфейс командной строки для выполнения операций шифрования и дешифровки, а также управления ключами и инициализационным вектором.

```python
import sys
import argparse
from typing import Callable
from pcbc import PCBC
from idea import IDEA


def encrypt_file(pcbc: PCBC, input_file: str, output_file: str, iv: bytes) -> None:
    """Encrypt the contents of input_file and write to output_file."""
    try:
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            plaintext = f_in.read()
            ciphertext = pcbc.encrypt(plaintext, iv)
            f_out.write(ciphertext)
        print(f"File encrypted and saved to {output_file}")
    except Exception as e:
        print(f"Encryption error: {e}")
        sys.exit(1)


def decrypt_file(pcbc: PCBC, input_file: str, output_file: str, iv: bytes) -> None:
    """Decrypt the contents of input_file and write to output_file."""
    try:
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            ciphertext = f_in.read()
            plaintext = pcbc.decrypt(ciphertext, iv)
            f_out.write(plaintext)
        print(f"File decrypted and saved to {output_file}")
    except Exception as e:
        print(f"Decryption error: {e}")
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="IDEA cipher with PCBC mode")
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help="Operation mode")
    parser.add_argument('input_file', help="Path to input file")
    parser.add_argument('output_file', help="Path to output file")
    parser.add_argument('key', help="Encryption/decryption key (16 bytes)")
    
    args = parser.parse_args()

    key = args.key.encode('utf-8')
    if len(key) != 16:
        print("Error: Key must be 16 bytes")
        sys.exit(1)

    try:
        idea = IDEA(key)
    except ValueError as e:
        print(f"Key error: {e}")
        sys.exit(1)

    pcbc = PCBC(idea)
    iv = b'\x00' * 8  # Initialization Vector

    operation: Callable[[PCBC, str, str, bytes], None] = encrypt_file if args.mode == 'encrypt' else decrypt_file
    operation(pcbc, args.input_file, args.output_file, iv)


if __name__ == "__main__":
    main()
```

#### `idea.py`

Реализация алгоритма IDEA (International Data Encryption Algorithm). Предоставляет методы для выполнения основных операций шифрования и дешифрования блоков данных, а также управления ключевыми раундами.

```python
import struct
from typing import Union, Sequence, List
UINT16_MASK: int = (1 << 16) - 1  # 0xFFFF

def is_uint16(value: int) -> bool:
	return 0 <= value < (1 << 16)


class IDEA:
    
    NUM_ROUNDS = 8
    KEYS_PER_ROUND = 6
    
    
    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes long")
        self.key = key
        self.round_keys = self.generate_round_keys(key)
        self.decryption_keys = self.generate_decryption_keys()

    def mul(self, x, y):
        """
        Performs multiplication modulo (2^16 + 1) for the IDEA algorithm.
        
        In the context of IDEA:
        - 0 is interpreted as 2^16 (65536 or 0x10000)
        - A result of 0x10001 (65537) is considered equivalent to 0
        """
        assert is_uint16(x)
        assert is_uint16(y)
        # Константа для модульного умножения
        MODULUS = 0x10000  # 2^16
        
        # Обработка специального случая: 0 представляется как 2^16
        if x == 0:
            x = MODULUS
        if y == 0:
            y = MODULUS
        
        # Выполнение модульного умножения
        result = (x * y) % (MODULUS + 1)
        
        # Если результат равен 2^16, возвращаем 0
        return 0 if result == MODULUS else result

    def mul_inv(self, x):
        """
        Calculate the multiplicative inverse of a number modulo 0x10001 (65537).

        The multiplicative inverse of x is a number y such that (x * y) % 65537 == 1.
        If x is 0, the function returns 0 as defined by the IDEA algorithm.

        Args:
            x (int): The number to find the inverse of.

        Returns:
            int: The multiplicative inverse of x modulo 65537, or 0 if x is 0.

        Raises:
            ValueError: If no inverse exists for the given x.
        """
        assert is_uint16(x)
        if x == 0:
            return 0
        else:
            return pow(x, 0xFFFF, 0x10001)  # By Fermat's little theorem
        # 65537 (0x10001) is a Fermat prime number (2^16 + 1).
        # By Fermat's Little Theorem: x^65536 ≡ 1 (mod 65537) for x ≠ 0.
        # Therefore, x^65535 ≡ x^(-1) (mod 65537), which is the multiplicative inverse.
        

    def add_inv(self, x):
        """
        Calculate the additive inverse of a number modulo 2^16 (65536).

        The additive inverse of x is a number y such that (x + y) % 65536 == 0.
        """
        assert is_uint16(x)
        return (-x) & UINT16_MASK

    def add(self, x, y):
        """
        Perform addition modulo 2^16 (65536).
        """
        assert is_uint16(x)
        assert is_uint16(y)
        return (x + y) & UINT16_MASK


    def generate_round_keys(self, key):
        """
        Generate 52 16-bit round keys from the 128-bit master key.
        """
        assert len(key) == 16
        
        round_keys = []
        key_bits = int.from_bytes(key, byteorder='big')
        assert 0 <= key_bits < (1 << 128)
        
        # Append the 16-bit prefix onto the suffix to yield a uint144
        key_bits = (key_bits << 16) | (key_bits >> 112)
        
        for i in range(self.NUM_ROUNDS * self.KEYS_PER_ROUND + 4):
            offset = (i * 16 + i // 8 * 25) % 128
            val = (key_bits >> (128 - offset)) & UINT16_MASK
            assert is_uint16(val)
            round_keys.append(val)
        assert len(round_keys) == 52
        return round_keys

    def generate_decryption_keys(self):
        """
        Generate the decryption keys from the encryption keys.
        
        This method creates a set of 52 16-bit decryption keys by inverting and 
        rearranging the encryption keys. The process ensures that decryption 
        with these keys will undo the encryption process.
        
        Returns:
            list: A list of 52 16-bit integers representing the decryption keys.
        
        Raises:
            ValueError: If invalid key components are encountered during the process.
        """
        encrypt_keys = self.round_keys
        assert len(encrypt_keys) % 6 == 4
        decrypt_keys: List[int] = []
        K1 = self.mul_inv(encrypt_keys[-4])
        K2 = self.add_inv(encrypt_keys[-3])
        K3 = self.add_inv(encrypt_keys[-2])
        K4 = self.mul_inv(encrypt_keys[-1])
        K5 = encrypt_keys[-6]
        K6 = encrypt_keys[-5]
        decrypt_keys.extend([K1, K2, K3, K4, K5, K6])
        
        for i in range(1, self.NUM_ROUNDS):
            j: int = i * self.KEYS_PER_ROUND
            K1 = self.mul_inv(encrypt_keys[-j - 4])
            K2 = self.add_inv(encrypt_keys[-j - 2])
            K3 = self.add_inv(encrypt_keys[-j - 3])
            K4 = self.mul_inv(encrypt_keys[-j - 1])
            K5 = encrypt_keys[-j - 6]
            K6 = encrypt_keys[-j - 5]
            decrypt_keys.extend([K1, K2, K3, K4, K5, K6])
        
        C1 = self.mul_inv(encrypt_keys[0])
        C2 = self.add_inv(encrypt_keys[1])
        C3 = self.add_inv(encrypt_keys[2])
        C4 = self.mul_inv(encrypt_keys[3])
        decrypt_keys.extend([C1, C2, C3, C4])
        assert len(decrypt_keys) == len(encrypt_keys)
        return decrypt_keys

    def encrypt_block(self, block):
        return self._crypt(block, "encrypt")

    def decrypt_block(self, block):
        return self._crypt(block, "decrypt")
    
    def _crypt(self, block: bytes, direction: str) -> bytes:
        assert len(self.key) == 16
        assert direction in ("encrypt", "decrypt")
        
        if len(block) != 8:
            raise ValueError("Block size must be 8 bytes")
        
        X1, X2, X3, X4 = struct.unpack('!4H', block)
        round_keys = self.decryption_keys if direction == "decrypt" else self.round_keys
        for round in range(self.NUM_ROUNDS):
            k = round * self.KEYS_PER_ROUND
            Y1 = self.mul(X1, round_keys[k])
            Y2 = self.add(X2, round_keys[k + 1])
            Y3 = self.add(X3, round_keys[k + 2])
            Y4 = self.mul(X4, round_keys[k + 3])

            T1 = Y1 ^ Y3
            T2 = Y2 ^ Y4
            T3 = self.mul(T1, round_keys[k + 4])
            T4 = self.add(T2, T3)
            T5 = self.mul(T4, round_keys[k + 5])
            T6 = self.add(T3, T5)

            X1 = self.add(Y1 ^ T5, 0)
            X2 = self.add(Y3 ^ T5, 0)
            X3 = self.add(Y2 ^ T6, 0)
            X4 = self.add(Y4 ^ T6, 0)

        # Final transformation
        k = 48
        C1 = self.mul(X1, round_keys[k])
        C2 = self.add(X3, round_keys[k + 1])
        C3 = self.add(X2, round_keys[k + 2])
        C4 = self.mul(X4, round_keys[k + 3])

        return struct.pack('!4H', C1, C2, C3, C4)
```

#### `pcbc.py`

Реализация режима шифрования PCBC (Propagating Cipher Block Chaining). Обеспечивает безопасность шифрования за счет использования цепочки блоков и добавления пропагирующего эффекта ошибок при дешифровке.

```python
from idea import IDEA

class PCBC:
    """
    Implements the Propagating Cipher Block Chaining (PCBC) mode of operation.
    """
    def __init__(self, cipher: IDEA):
        """Initialize PCBC with a block cipher object."""
        self.cipher = cipher

    def pad(self, data: bytes) -> bytes:
        """
        Apply PKCS#7 padding to the input data.
        Ensures the data length is a multiple of the block size (8 bytes).
        """
        padding_len = 8 - (len(data) % 8)
        return data + bytes([padding_len] * padding_len)
    
    def xor_blocks(self, block1: bytes, block2: bytes) -> bytes:
        return bytes(b1 ^ b2 for b1, b2 in zip(block1, block2))

    def unpad(self, data: bytes) -> bytes:
        """
        Remove PKCS#7 padding from the decrypted data.
        Raises ValueError if padding is invalid.
        """
        padding_len = data[-1]
        if padding_len < 1 or padding_len > 8:
            raise ValueError("Invalid padding")
        return data[:-padding_len]

    def encrypt(self, plaintext: bytes, iv: bytes) -> bytes:
        """
        Encrypt the plaintext using PCBC mode.
        
        Args:
            plaintext: The data to encrypt.
            iv: Initialization vector (8 bytes).
        
        Returns:
            Encrypted ciphertext.
        """
        plaintext = self.pad(plaintext)
        ciphertext = b''
        prev_ciphertext = iv
        prev_plaintext = bytes(8)
        for i in range(0, len(plaintext), 8):
            block = plaintext[i:i + 8]
            
            # PCBC mode encrypt: encrypt(plaintext_block XOR (prev_ciphertext XOR prev_plaintext))
            ciphertext_block = self.xor_blocks(block, self.xor_blocks(prev_ciphertext, prev_plaintext))
        
            encrypted = self.cipher.encrypt_block(ciphertext_block)
            ciphertext += encrypted
            
            prev_ciphertext = encrypted
            prev_plaintext = block
        return ciphertext

    def decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        """
        Decrypt the ciphertext using PCBC mode.
        
        Args:
            ciphertext: The data to decrypt.
            iv: Initialization vector (8 bytes).
        
        Returns:
            Decrypted plaintext with padding removed.
        
        Raises:
            ValueError if ciphertext length is not a multiple of 8 bytes.
        """
        if len(ciphertext) % 8 != 0:
            raise ValueError("Ciphertext length must be multiple of 8 bytes")
        plaintext = b''
        prev_plaintext = bytes(8)
        prev_ciphertext= iv
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i + 8]
            
            decrypted = self.cipher.decrypt_block(block)
            
            # PCBC mode decrypt: (prev_plaintext XOR prev_ciphertext) XOR decrypt(ciphertext_block)
            plaintext_block = self.xor_blocks(self.xor_blocks(prev_plaintext, prev_ciphertext), decrypted)
            plaintext += plaintext_block
            
            prev_ciphertext = block
            prev_plaintext = plaintext_block
            
        return self.unpad(plaintext)
```

#### `test_idea_pcbc_cipher.py`

Набор тестов для проверки корректности реализации алгоритма IDEA и режима шифрования PCBC. Использует библиотеку `pytest` для организации и выполнения тестовых случаев.

```python
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
```

#### `test_idea_pcbc_cipher.py`

Набор тестов для проверки корректности реализации алгоритма IDEA и режима шифрования PCBC. Использует библиотеку `pytest` для организации и выполнения тестовых случаев.

```python
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
```

### `test_idea_pcbc_cipher.py`

Набор тестов для проверки корректности реализации алгоритма IDEA и режима шифрования PCBC. Использует библиотеку `pytest` для организации и выполнения тестовых случаев.

```python:Cryptography/lab1.2/tests/test_idea_pcbc_cipher.py
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
```

## Результаты работы программы

### Пример 1: Шифрование

**Исходный текст (`input.txt`):**

```text
Lorem Ipsum - это текст-"рыба", часто используемый в печати и вэб-дизайне. Lorem Ipsum является стандартной "рыбой" для текстов на латинице с начала XVI века. В то время некий безымянный печатник создал большую коллекцию размеров и форм шрифтов, используя Lorem Ipsum для распечатки образцов. Lorem Ipsum не только успешно пережил без заметных изменений пять веков, но и перешагнул в электронный дизайн. Его популяризации в новое время послужили публикация листов Letraset с образцами Lorem Ipsum в 60-х годах и, в более недавнее время, программы электронной вёрстки типа Aldus PageMaker, в шаблонах которых используется Lorem Ipsum.
```

**Команда для шифрования:**

```bash
python src/main.py encrypt input.txt encrypted.bin 16bytekeyforIDEA
```

**Результат:**

Вывод в консоль:

```text
File encrypted and saved to encrypted.bin
```

### Пример 2: Дешифровка

**Исходный текст (`encrypted.bin`):**

*(Двоичные данные, не представляемые в текстовом формате)*

**Команда для дешифровки:**

```bash
python src/main.py decrypt encrypted.bin decrypted.txt 16bytekeyforIDEA
```

**Результат:**

Вывод в консоль:

```text
File decrypted and saved to decrypted.txt
```

**Файл `decrypted.txt`:**

```text
Lorem Ipsum - это текст-"рыба", часто используемый в печати и вэб-дизайне. Lorem Ipsum является стандартной "рыбой" для текстов на латинице с начала XVI века. В то время некий безымянный печатник создал большую коллекцию размеров и форм шрифтов, используя Lorem Ipsum для распечатки образцов. Lorem Ipsum не только успешно пережил без заметных изменений пять веков, но и перешагнул в электронный дизайн. Его популяризации в новое время послужили публикация листов Letraset с образцами Lorem Ipsum в 60-х годах и, в более недавнее время, программы электронной вёрстки типа Aldus PageMaker, в шаблонах которых используется Lorem Ipsum.
```

## Заключение

В ходе выполнения лабораторной работы была реализована система симметричного блочного шифрования на основе алгоритма IDEA в режиме PCBC. Программа успешно шифрует и дешифрует файлы, обеспечивая надежную защиту данных. Полученные результаты подтверждают корректность реализации алгоритма и режима шифрования.

## Классы и Методы

### `IDEA` Класс

Реализует алгоритм IDEA.

```python
class IDEA:
    NUM_ROUNDS = 8
    KEYS_PER_ROUND = 6
    
    def __init__(self, key):
        ...
    
    def mul(self, x, y):
        ...
    
    def mul_inv(self, x):
        ...
    
    def add_inv(self, x):
        ...
    
    def add(self, x, y):
        ...
    
    def generate_round_keys(self, key):
        ...
    
    def generate_decryption_keys(self):
        ...
    
    def encrypt_block(self, block):
        ...
    
    def decrypt_block(self, block):
        ...
    
    def _crypt(self, block: bytes, direction: str) -> bytes:
        ...
```

### `PCBC` Класс

Реализует режим шифрования PCBC.

```python
class PCBC:
    def __init__(self, cipher: IDEA):
        ...
    
    def pad(self, data: bytes) -> bytes:
        ...
    
    def xor_blocks(self, block1: bytes, block2: bytes) -> bytes:
        ...
    
    def unpad(self, data: bytes) -> bytes:
        ...
    
    def encrypt(self, plaintext: bytes, iv: bytes) -> bytes:
        ...
    
    def decrypt(self, ciphertext: bytes, iv: bytes) -> bytes:
        ...
```

### `main.py` Функции

```python
def encrypt_file(pcbc: PCBC, input_file: str, output_file: str, iv: bytes) -> None:
    ...
def decrypt_file(pcbc: PCBC, input_file: str, output_file: str, iv: bytes) -> None:
    ...
def main() -> None:
    ...
```

### `test_idea_pcbc_cipher.py` Тесты

```python
def test_idea_key_length_valid(valid_key):
    ...
def test_idea_key_length_invalid(invalid_key):
    ...
def test_addition(cipher: IDEA):
    ...
def test_subtraction(cipher: IDEA):
    ...
def test_generate_round_keys(cipher: IDEA):
    ...
def test_encrypt_decrypt(pcbc: PCBC):
    ...
def test_padding(pcbc: PCBC):
    ...
def test_unpad_invalid(pcbc: PCBC):
    ...
def test_decrypt_invalid_block_size(pcbc: PCBC):
    ...
def test_encrypt_decrypt_empty(pcbc: PCBC):
    ...
def test_encrypt_decrypt_large_data(pcbc: PCBC):
    ...
```

## Пояснения

- **Инициализация Вектора (IV):** В данном проекте используется вектор инициализации `iv = b'\x00' * 8`. Для повышения безопасности рекомендуется использовать случайные IV при каждом шифровании.
  
- **Ключ Шифрования:** Ключ должен быть 16-байтовым строковым значением. Неправильная длина ключа приведет к ошибке.
  
- **Обработка Исключений:** Все операции шифрования и дешифровки обернуты в блоки `try-except` для корректной обработки ошибок.

## Запуск Тестов

Для проверки корректности реализации алгоритмов предусмотрены тесты, расположенные в директории `tests/`. Для запуска тестов используйте следующую команду:

```bash
pytest tests -v
```

## Лицензия

Этот проект распространяется под лицензией MIT. Смотрите файл [LICENSE](LICENSE) для подробностей.