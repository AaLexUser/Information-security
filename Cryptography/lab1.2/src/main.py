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