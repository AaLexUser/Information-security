import math
from omegaconf import DictConfig
import hydra
from tqdm import tqdm
import logging
logger = logging.getLogger(__name__)

# RSA cryptanalysis using repeated encryption
def int_to_bytes(m):
    """
    Convert an integer to bytes.
    """
    hex_str = hex(m)[2:]
    if len(hex_str) % 2:
        hex_str = '0' + hex_str
    return bytes.fromhex(hex_str)

def repeated_encryption_attack(y, e, N):
    """
    Perform RSA cryptanalysis using repeated encryption attack.
    Constructs the sequence:
        y1 = y
        yi = y_{i-1}^{e} mod N for i > 1
    Continues until y_i = y, then returns y_{i-1} as the plaintext x.
    """
    y_current = y
    i = 1
    y_sequence = [y_current]

    while True:
        y_next = pow(y_current, e, N)
        if y_next == y:
            logger.debug(f"Cycle detected at iteration {i+1}.")
            break
        y_sequence.append(y_next)
        y_current = y_next
        i += 1

    if i == 0:
        logger.debug("No repetition detected.")
        return None

    plaintext = y_sequence[-1]
    logger.debug(f"Plaintext x found: {plaintext}")
    return plaintext


@hydra.main(version_base=None, config_path=".", config_name="config")
def main(cfg: DictConfig):
    N = cfg.N
    e = cfg.e
    ciphertexts = cfg.c

    print(f"N = {N}")
    print(f"e = {e}")
    print(f"Ciphertexts = {ciphertexts}")

    # Decrypt each ciphertext block using repeated encryption attack
    print("Performing repeated encryption attack on ciphertext blocks...")
    decrypted_bytes = b''
    for idx, c in tqdm(enumerate(ciphertexts, start=1), total=len(ciphertexts), desc="Decrypting Ciphertext Blocks"):
        logger.debug(f"Decrypting ciphertext block {idx}: {c}")
        plaintext_int = repeated_encryption_attack(c, e, N)
        if plaintext_int is None:
            print(f"Failed to decrypt ciphertext block {idx}.")
            continue
        decrypted_bytes += int_to_bytes(plaintext_int)

    try:
        plaintext = decrypted_bytes.decode('cp1251')
        print(f"Plaintext: {plaintext}")
    except UnicodeDecodeError:
        print("Decrypted bytes could not be decoded to cp1251. Raw bytes:")
        print(decrypted_bytes)

if __name__ == "__main__":
    main()