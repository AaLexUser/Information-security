import math
from omegaconf import DictConfig
import hydra
from tqdm import tqdm
import logging

logger = logging.getLogger(__name__)


def int_to_bytes(m):
    """
    Convert an integer to bytes.
    """
    hex_str = hex(m)[2:]
    if len(hex_str) % 2:
        hex_str = '0' + hex_str
    return bytes.fromhex(hex_str)


def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm.
    Returns a tuple of (gcd, x, y), where gcd is the gcd of a and b,
    and x, y satisfy the equation: a*x + b*y = gcd
    """
    if a == 0:
        return (b, 0, 1)
    else:
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return (gcd, x, y)


def reading_attack(y1, e1, y2, e2, N):
    """
    Perform RSA cryptanalysis using the Reading Attack (Бесключевое чтение).
    Given two ciphertexts y1 = x^e1 mod N and y2 = x^e2 mod N,
    recover the original plaintext x.
    """
    gcd, r, s = extended_gcd(e1, e2)
    if gcd != 1:
        logger.error(
            "Exponents e1 and e2 are not coprime. Attack cannot be performed.")
        return None

    # Compute x = (y1^r * y2^s) mod N
    x = (pow(y1, r, N) * pow(y2, s, N)) % N

    logger.debug(f"Recovered plaintext x: {x}")
    return x


@hydra.main(version_base=None, config_path=".", config_name="config")
def main(cfg: DictConfig):
    N = cfg.N
    e1 = cfg.e1
    e2 = cfg.e2
    c1 = cfg.c1
    c2 = cfg.c2

    print(f"N = {N}")
    print(f"e1 = {e1}")
    print(f"e2 = {e2}")
    print(f"c1 = {c1}")
    print(f"c2 = {c2}")

    # Perform Reading Attack on each ciphertext pair
    print("Performing Reading Attack on ciphertext pairs...")
    decrypted_bytes = b''

    for idx, (y1, y2) in tqdm(enumerate(zip(c1, c2), start=1), total=len(c1), desc="Decrypting Ciphertext Pairs"):
        logger.debug(f"Decrypting ciphertext pair {idx}: y1={y1}, y2={y2}")
        plaintext_int = reading_attack(y1, e1, y2, e2, N)
        if plaintext_int is None:
            print(f"Failed to decrypt ciphertext pair {idx}.")
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
