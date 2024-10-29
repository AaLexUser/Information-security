import math
from omegaconf import DictConfig
import hydra

# RSA cryptanalysis using Fermat factorization

def fermat_factor(N):
    """
    Perform Fermat's factorization on N.
    Returns a tuple of factors (p, q).
    """
    t = math.isqrt(N)
    if t * t < N:
        t += 1
    s2 = t * t - N
    while not is_perfect_square(s2):
        t += 1
        s2 = t * t - N
    s = math.isqrt(s2)
    p = t + s
    q = t - s
    return p, q

def is_perfect_square(n):
    """
    Check if n is a perfect square.
    """
    return math.isqrt(n) ** 2 == n


def decrypt_block(c, d, N):
    """
    Decrypt a single ciphertext block.
    """
    return pow(c, d, N)

def int_to_bytes(m):
    """
    Convert an integer to bytes.
    """
    hex_str = hex(m)[2:]
    if len(hex_str) % 2:
        hex_str = '0' + hex_str
    return bytes.fromhex(hex_str)


@hydra.main(version_base=None, config_path=".", config_name="config")
def main(cfg: DictConfig):
    N = cfg.N
    e = cfg.e
    ciphertexts = cfg.c

    print(f"N = {N}")
    print(f"e = {e}")
    print(f"Ciphertexts = {ciphertexts}")

    # Factor N to find p and q
    print("Factoring N using Fermat's method...")
    p, q = fermat_factor(N)
    print(f"Factors found: p = {p}, q = {q}")

    # Compute phi(N)
    phi = (p - 1) * (q - 1)
    print(f"phi(N) = {phi}")

    # Compute the private exponent d
    d = pow(e, -1, phi)
    print(f"Private exponent d = {d}")

    # Decrypt each ciphertext block
    print("Decrypting ciphertext blocks...")
    decrypted_bytes = b''.join([int_to_bytes(decrypt_block(c, d, N)) for c in ciphertexts])

    try:
        plaintext = decrypted_bytes.decode('cp1251')
        print(f"Plaintext: {plaintext}")
    except UnicodeDecodeError:
        print("Decrypted bytes could not be decoded to UTF-8. Raw bytes:")
        print(decrypted_bytes)

if __name__ == "__main__":
    main()
