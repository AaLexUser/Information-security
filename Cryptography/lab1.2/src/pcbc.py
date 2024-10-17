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
