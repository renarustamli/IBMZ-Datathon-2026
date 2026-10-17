import hashlib
import math
import secrets

from sympy import randprime

E = 65537  # standard public exponent


def generate_keypair(bits=32):
    """Make a toy RSA key. Two `bits`-bit primes, so n is about 2*bits long (64 by default)."""
    while True:
        p = randprime(2 ** (bits - 1), 2 ** bits)
        q = randprime(2 ** (bits - 1), 2 ** bits)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(E, phi) != 1:  # E must share no factors with phi, else pick new primes
            continue
        n = p * q
        d = pow(E, -1, phi)  # private exponent (modular inverse)
        return (n, E), (n, d)  # (public key, private key)


def encrypt(message_int, public_key):
    n, e = public_key
    return pow(message_int, e, n)


def decrypt(cipher_int, private_key):
    n, d = private_key
    return pow(cipher_int, d, n)


def new_secret():
    """A random 32-bit secret. Always smaller than n, so it fits in the lock."""
    return secrets.randbits(32)


def derive_aes_key(secret_int):
    """Turn the small secret into a 32-byte AES key by hashing it."""
    return hashlib.sha256(secret_int.to_bytes(8, "big")).digest()


if __name__ == "__main__":
    # Self-test: lock and unlock 200 secrets with 200 different keys
    for _ in range(200):
        public, private = generate_keypair()
        secret = new_secret()
        locked = encrypt(secret, public)
        assert decrypt(locked, private) == secret, "unlock failed"
        assert len(derive_aes_key(secret)) == 32
    n = public[0]
    print(f"All 200 round trips OK. Example n has {n.bit_length()} bits: {n}")
