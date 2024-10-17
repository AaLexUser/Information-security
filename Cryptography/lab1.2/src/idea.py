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
        
