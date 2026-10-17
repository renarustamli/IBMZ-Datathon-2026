import hashlib
import json
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sympy import factorint

# The attacker ONLY reads recordings. It never touches the server's code, memory or key.
CAPTURES = Path(__file__).parent.parent / "captures"


def find(frames, kind):
    for f in frames:
        if f["frame"].get("type") == kind:
            return f["frame"]
    return None


def crack_session(path):
    """Returns (record, seconds) on success, or (None, reason) on failure."""
    start = time.time()
    try:
        frames = json.loads(path.read_text())
        hello = find(frames, "hello")
        if hello is None or "n" not in hello:
            return None, "no RSA public key in this recording (nothing to factor)"
        key_msg = find(frames, "key")
        request = find(frames, "request")
        reply = find(frames, "data")
        if not (key_msg and request and reply):
            return None, "recording is incomplete"

        n, e = hello["n"], hello["e"]

        # Step 1: break the tiny lock by finding its two prime factors
        factors = factorint(n)
        if len(factors) != 2 or any(v != 1 for v in factors.values()):
            return None, "could not split the key into two primes"
        p, q = list(factors)

        # Step 2: rebuild the private key and unlock the secret
        d = pow(e, -1, (p - 1) * (q - 1))
        secret = pow(key_msg["locked_secret"], d, n)

        # Step 3: rebuild the session key (same public recipe the protocol uses) and read the data
        aes = AESGCM(hashlib.sha256(secret.to_bytes(8, "big")).digest())
        record = json.loads(
            aes.decrypt(bytes.fromhex(
                reply["nonce"]), bytes.fromhex(reply["ct"]), None)
        )
        return record, time.time() - start
    except Exception as ex:
        return None, f"failed: {type(ex).__name__}"


def main():
    folder = Path(sys.argv[1]) if len(sys.argv) > 1 else CAPTURES
    files = sorted(folder.glob("session_*.json"))
    print(f"Loaded {len(files)} recordings from {folder}\n")

    cracked = 0
    total_time = 0.0
    for path in files:
        record, info = crack_session(path)
        if record is None:
            print(f"{path.name}: FAILED - {info}")
            continue
        cracked += 1
        total_time += info
        print(
            f"{path.name}: {record.get('name')} | account {record.get('account_number')} "
            f"| balance {record.get('balance')} | cracked in {info:.2f}s"
        )

    print(f"\nRecovered secret data from {cracked} of {len(files)} recordings "
          f"in {total_time:.2f}s total")


if __name__ == "__main__":
    main()
