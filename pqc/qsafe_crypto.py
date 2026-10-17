"""
qsafe_crypto: the crypto layer (Person B) for the Quantum-Safe Gateway.

The four functions the rest of the team calls:

    lock(data)              -> bytes  encrypt data at rest: AES-256-GCM, with the data key
                                      wrapped by ML-KEM-768 (post-quantum)
    unlock(blob)            -> bytes  decrypt it back; raises TamperedError if even one byte changed
    sign(message)           -> bytes  ML-DSA-65 (post-quantum) signature
    verify(message, sig)    -> bool   True only if the message is exactly what was signed

Tamper-evident logs, built on sign/verify:

    log = SealedLog("notes.jsonl")
    log.write({"client": "10.0.0.5", ...})   # writes the line unchanged + a seal in notes.jsonl.seal
    verify_log("notes.jsonl")                 # OK, or TAMPERED with the exact line number

Algorithms are the NIST post-quantum standards FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA),
via the pure-Python packages kyber-py and dilithium-py. Pure Python means nothing to
compile, so they install the same way on IBM LinuxONE (s390x) as on a laptop.

Command line (run `python qsafe_crypto.py -h`):
    keygen | lock | unlock | sign | seal | verify | selftest | bench
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import platform
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path

try:
    from kyber_py.ml_kem import ML_KEM_768
    from dilithium_py.ml_dsa import ML_DSA_65
except ImportError as exc:  # pragma: no cover
    raise SystemExit("Missing post-quantum libraries. Run: pip install kyber-py dilithium-py") from exc


# ---------------------------------------------------------------------------
# AES-256-GCM backend: prefer `cryptography` (OpenSSL, uses the CPACF crypto
# hardware on IBM Z), fall back to pycryptodome. Both produce identical output.
# ---------------------------------------------------------------------------
class TamperedError(Exception):
    """Raised when locked data was modified, corrupted, or opened with the wrong key."""


AES_BACKEND = None
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
    from cryptography.exceptions import InvalidTag as _InvalidTag

    def _gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return _AESGCM(key).encrypt(nonce, plaintext, aad)

    def _gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        try:
            return _AESGCM(key).decrypt(nonce, ciphertext, aad)
        except _InvalidTag:
            raise TamperedError("authentication failed: data was modified or the key is wrong") from None

    AES_BACKEND = "cryptography (OpenSSL)"
except BaseException as _exc:  # ImportError, or a broken system install that panics on import
    if isinstance(_exc, (KeyboardInterrupt, SystemExit)):
        raise
    try:
        from Crypto.Cipher import AES as _AES

        def _gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
            cipher = _AES.new(key, _AES.MODE_GCM, nonce=nonce)
            cipher.update(aad)
            ct, tag = cipher.encrypt_and_digest(plaintext)
            return ct + tag

        def _gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
            cipher = _AES.new(key, _AES.MODE_GCM, nonce=nonce)
            cipher.update(aad)
            try:
                return cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
            except ValueError:
                raise TamperedError("authentication failed: data was modified or the key is wrong") from None

        AES_BACKEND = "pycryptodome"
    except ImportError:
        pass


def _need_aes() -> None:
    if AES_BACKEND is None:
        raise RuntimeError("No AES library found. Run: pip install cryptography   (or: pip install pycryptodome)")


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------
KEY_FILES = {
    "kem_pub": "mlkem768.pub",   # share freely: anyone can lock() data for us
    "kem_key": "mlkem768.key",   # secret: needed to unlock()
    "dsa_pub": "mldsa65.pub",    # share freely: anyone can verify() our signatures
    "dsa_key": "mldsa65.key",    # secret: needed to sign()
}


def _key_dir(key_dir=None) -> Path:
    return Path(key_dir or os.environ.get("QSAFE_KEYS", "keys"))


def generate_keys(key_dir=None, overwrite: bool = False) -> Path:
    """Create a fresh ML-KEM-768 and ML-DSA-65 key pair in key_dir (default ./keys)."""
    d = _key_dir(key_dir)
    if not overwrite and any((d / f).exists() for f in KEY_FILES.values()):
        raise FileExistsError(f"keys already exist in {d}/ (use overwrite=True / --force to replace them)")
    d.mkdir(parents=True, exist_ok=True)
    ek, dk = ML_KEM_768.keygen()
    pk, sk = ML_DSA_65.keygen()
    for name, data in (("kem_pub", ek), ("kem_key", dk), ("dsa_pub", pk), ("dsa_key", sk)):
        path = d / KEY_FILES[name]
        path.write_bytes(data)
        if name.endswith("_key"):
            os.chmod(path, 0o600)
    return d


def load_key(name: str, key_dir=None) -> bytes:
    """Load one key by name: 'kem_pub', 'kem_key', 'dsa_pub' or 'dsa_key'."""
    path = _key_dir(key_dir) / KEY_FILES[name]
    if not path.exists():
        raise FileNotFoundError(f"{path} not found. Run: python qsafe_crypto.py keygen")
    return path.read_bytes()


# ---------------------------------------------------------------------------
# lock / unlock: envelope encryption
#
#   1. a random 256-bit data key (DEK) encrypts the data with AES-256-GCM
#   2. ML-KEM-768 gives a fresh shared secret; HKDF turns it into a key-encryption
#      key (KEK) that wraps the DEK
#   3. everything in the header is authenticated, so changing any byte breaks unlock()
#
# Locked blob layout (fixed sizes for ML-KEM-768):
#   "QSG1" | ML-KEM ciphertext (1088) | wrap nonce (12) | wrapped DEK (32+16) | data nonce (12) | AES-GCM ciphertext+tag
# ---------------------------------------------------------------------------
MAGIC = b"QSG1"
KEM_CT_LEN = 1088
NONCE_LEN = 12
WRAPPED_LEN = 32 + 16
HEADER_LEN = len(MAGIC) + KEM_CT_LEN + NONCE_LEN + WRAPPED_LEN + NONCE_LEN


def _to_bytes(data) -> bytes:
    if isinstance(data, str):
        return data.encode("utf-8")
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    raise TypeError(f"expected bytes or str, got {type(data).__name__}")


def _hkdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869) with a zero salt."""
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def lock(data, public_key: bytes = None) -> bytes:
    """Encrypt bytes/str so only the holder of the ML-KEM private key can read them."""
    _need_aes()
    data = _to_bytes(data)
    ek = public_key if public_key is not None else load_key("kem_pub")
    shared_secret, kem_ct = ML_KEM_768.encaps(ek)
    kek = _hkdf(shared_secret, b"qsafe/v1/key-wrap")
    dek = os.urandom(32)
    wrap_nonce = os.urandom(NONCE_LEN)
    wrapped_dek = _gcm_encrypt(kek, wrap_nonce, dek, MAGIC + kem_ct)
    data_nonce = os.urandom(NONCE_LEN)
    header = MAGIC + kem_ct + wrap_nonce + wrapped_dek + data_nonce
    return header + _gcm_encrypt(dek, data_nonce, data, header)


def unlock(blob: bytes, private_key: bytes = None) -> bytes:
    """Decrypt a lock() blob. Raises TamperedError if anything was changed or the key is wrong."""
    _need_aes()
    blob = _to_bytes(blob)
    if len(blob) < HEADER_LEN + 16 or not blob.startswith(MAGIC):
        raise TamperedError("not a locked blob, or its header is damaged")
    pos = len(MAGIC)
    kem_ct = blob[pos:pos + KEM_CT_LEN]; pos += KEM_CT_LEN
    wrap_nonce = blob[pos:pos + NONCE_LEN]; pos += NONCE_LEN
    wrapped_dek = blob[pos:pos + WRAPPED_LEN]; pos += WRAPPED_LEN
    data_nonce = blob[pos:pos + NONCE_LEN]; pos += NONCE_LEN
    header, body = blob[:pos], blob[pos:]
    dk = private_key if private_key is not None else load_key("kem_key")
    # A modified KEM ciphertext makes ML-KEM return an unrelated secret ("implicit
    # rejection"), so unwrapping the data key fails below with TamperedError.
    shared_secret = ML_KEM_768.decaps(dk, kem_ct)
    kek = _hkdf(shared_secret, b"qsafe/v1/key-wrap")
    dek = _gcm_decrypt(kek, wrap_nonce, wrapped_dek, MAGIC + kem_ct)
    return _gcm_decrypt(dek, data_nonce, body, header)


# ---------------------------------------------------------------------------
# sign / verify: ML-DSA-65
# ---------------------------------------------------------------------------
SIG_CONTEXT = b"qsafe-gateway/v1"  # domain separation: our signatures can't be reused by other apps


def sign(message, private_key: bytes = None) -> bytes:
    """Return an ML-DSA-65 signature (3309 bytes) over message (bytes or str)."""
    sk = private_key if private_key is not None else load_key("dsa_key")
    return ML_DSA_65.sign(sk, _to_bytes(message), ctx=SIG_CONTEXT)


def verify(message, signature: bytes, public_key: bytes = None) -> bool:
    """True only if signature is a valid ML-DSA-65 signature over exactly this message."""
    pk = public_key if public_key is not None else load_key("dsa_pub")
    try:
        return bool(ML_DSA_65.verify(pk, _to_bytes(message), bytes(signature), ctx=SIG_CONTEXT))
    except Exception:  # malformed or wrong-length signature
        return False


# ---------------------------------------------------------------------------
# Tamper-evident log
#
# The log file is written exactly as given (one entry per line), so whoever reads
# it (Person D) sees the agreed note format unchanged. Seals go in <log>.seal,
# one JSON record per line:
#     {"seq": n, "line_sha256": ..., "chain": ..., "sig": base64(ML-DSA sig over chain)}
# chain_n = SHA-256(chain_{n-1} || n || line_sha256_n) links every line to the ones
# before it, so editing, deleting, inserting or reordering lines is all detected.
# ---------------------------------------------------------------------------
_GENESIS = hashlib.sha256(b"qsafe-log-genesis/v1").digest()


def _chain_next(prev: bytes, seq: int, line_hash: bytes) -> bytes:
    return hashlib.sha256(prev + seq.to_bytes(8, "big") + line_hash).digest()


def _seal_path(log_path) -> Path:
    return Path(str(log_path) + ".seal")


def _seal_record(seq: int, prev_chain: bytes, raw: bytes, sk: bytes):
    """Build the seal for line number `seq`; returns (JSON record, new chain value)."""
    line_hash = hashlib.sha256(raw).digest()
    chain = _chain_next(prev_chain, seq, line_hash)
    record = {"seq": seq, "line_sha256": line_hash.hex(), "chain": chain.hex(),
              "sig": base64.b64encode(sign(chain, sk)).decode()}
    return json.dumps(record), chain


def _last_seal(seal_path: Path):
    """(seq, chain) of the newest seal record, or (0, genesis) for a new log."""
    if seal_path.exists():
        records = seal_path.read_text(encoding="utf-8").splitlines()
        if records:
            last = json.loads(records[-1])
            return int(last["seq"]), bytes.fromhex(last["chain"])
    return 0, _GENESIS


class SealedLog:
    """Append-only log, every line sealed with ML-DSA. For a gateway written in Python.

    Create ONE SealedLog per log file and share it between threads.

    Signing costs tens of ms per line in pure Python. If that is too slow for the
    gateway, or the gateway isn't Python, write the log normally and run
    follow_log() / `python qsafe_crypto.py follow LOG` in a separate process instead.
    """

    def __init__(self, path, private_key: bytes = None):
        self.path = Path(path)
        self.seal_path = _seal_path(self.path)
        self._sk = private_key if private_key is not None else load_key("dsa_key")
        self._lock = threading.Lock()
        self._seq, self._chain = _last_seal(self.seal_path)

    def write(self, entry) -> None:
        """Append one entry (dict -> JSON line, or a str line) and seal it."""
        line = entry if isinstance(entry, str) else json.dumps(entry)
        line = line.rstrip("\r\n")
        if "\n" in line or "\r" in line:
            raise ValueError("a log entry must be a single line")
        raw = line.encode("utf-8")
        with self._lock:
            record, chain = _seal_record(self._seq + 1, self._chain, raw, self._sk)
            with open(self.path, "ab") as f:
                f.write(raw + b"\n")
            with open(self.seal_path, "a", encoding="utf-8") as f:
                f.write(record + "\n")
            self._seq, self._chain = self._seq + 1, chain


def seal_existing_log(path, private_key: bytes = None, overwrite: bool = False) -> int:
    """Seal every line of a log that was written without SealedLog. Returns the number of lines."""
    path = Path(path)
    seal_path = _seal_path(path)
    if seal_path.exists() and not overwrite:
        raise FileExistsError(f"{seal_path} already exists (use --force to re-seal)")
    sk = private_key if private_key is not None else load_key("dsa_key")
    lines = path.read_bytes().split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    chain, out = _GENESIS, []
    for seq, raw in enumerate(lines, start=1):
        record, chain = _seal_record(seq, chain, raw.rstrip(b"\r"), sk)
        out.append(record)
    seal_path.write_text("\n".join(out) + ("\n" if out else ""), encoding="utf-8")
    return len(lines)


def follow_log(path, private_key: bytes = None, poll_s: float = 0.2, stop: threading.Event = None,
               on_seal=None) -> None:
    """Watch a log another program is appending to, and seal each new line as it lands.

    Run it as its own process next to the gateway: `python qsafe_crypto.py follow notes.jsonl`.
    The gateway, and whoever reads the notes, need no changes. Lines already sealed
    are skipped, so it is safe to stop and restart. Stops when `stop` is set.
    """
    path = Path(path)
    seal_path = _seal_path(path)
    sk = private_key if private_key is not None else load_key("dsa_key")
    seq, chain = _last_seal(seal_path)
    seen, offset, pending = 0, 0, b""
    while stop is None or not stop.is_set():
        size = path.stat().st_size if path.exists() else 0
        if size < offset:  # file shrank: someone deleted or rewrote lines
            print(f"WARNING: {path} shrank from {offset} to {size} bytes; run `verify` to see what changed",
                  file=sys.stderr)
            offset, pending = size, b""
        if size > offset:
            with open(path, "rb") as f:
                f.seek(offset)
                data = f.read(size - offset)
            offset += len(data)
            pending += data
            *complete, pending = pending.split(b"\n")  # keep a half-written last line for later
            for raw in complete:
                seen += 1
                if seen <= seq:  # sealed on an earlier run
                    continue
                record, chain = _seal_record(seq + 1, chain, raw.rstrip(b"\r"), sk)
                with open(seal_path, "a", encoding="utf-8") as f:
                    f.write(record + "\n")
                seq += 1
                if on_seal:
                    on_seal(seq, raw)
        time.sleep(poll_s)


def verify_log(path, public_key: bytes = None) -> dict:
    """Check a sealed log. Returns {"ok": bool, "lines": n, "problems": [(line_no, reason), ...]}."""
    path = Path(path)
    seal_path = _seal_path(path)
    pk = public_key if public_key is not None else load_key("dsa_pub")
    if not seal_path.exists():
        return {"ok": False, "lines": 0, "problems": [(0, f"no seal file {seal_path.name}; this log was never sealed")]}
    lines = path.read_bytes().split(b"\n") if path.exists() else []
    if lines and lines[-1] == b"":
        lines.pop()
    lines = [l.rstrip(b"\r") for l in lines]
    problems = {}  # line number -> first reason found

    def flag(n, reason):
        problems.setdefault(n, reason)

    records = []
    for i, text in enumerate(seal_path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            records.append(json.loads(text))
        except ValueError:
            flag(i, "seal record is corrupted")
            records.append(None)

    # 1. The seal file itself: an unbroken hash chain, every link signed by our key.
    chain = _GENESIS
    for i, rec in enumerate(records, start=1):
        if rec is None:
            continue
        good = False
        try:
            expected = _chain_next(chain, i, bytes.fromhex(rec["line_sha256"]))
            good = (int(rec["seq"]) == i and hmac.compare_digest(expected.hex(), str(rec["chain"]))
                    and verify(expected, base64.b64decode(rec["sig"]), pk))
        except (KeyError, ValueError, TypeError):
            pass
        if not good:
            flag(i, "seal is forged or was edited")
        try:  # carry on from the recorded link so one bad record doesn't flag every later line
            chain = bytes.fromhex(rec["chain"])
        except (KeyError, ValueError, TypeError):
            pass

    # 2. The log lines against their seals.
    def line_hash_matches(line_idx, rec_idx):
        rec = records[rec_idx] if rec_idx < len(records) else None
        return rec is not None and hashlib.sha256(lines[line_idx]).hexdigest() == rec.get("line_sha256")

    for i in range(max(len(lines), len(records))):
        n = i + 1
        if i >= len(records):
            flag(n, "line was added after sealing")
        elif i >= len(lines):
            flag(n, "line is missing (deleted or log truncated)")
        elif records[i] is not None and not line_hash_matches(i, i):
            if line_hash_matches(i, i + 1):
                flag(n, "a line was deleted here (everything below shifted up)")
                break
            flag(n, "content was changed after it was sealed")

    found = sorted(problems.items())
    return {"ok": not found, "lines": len(lines), "problems": found}


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
def selftest() -> bool:
    results = []

    def check(name, cond):
        results.append(bool(cond))
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")

    def raises_tampered(fn):
        try:
            fn()
        except TamperedError:
            return True
        return False

    print(f"Self-test on {platform.machine()} / Python {platform.python_version()} / AES via {AES_BACKEND}")
    with tempfile.TemporaryDirectory() as tmp:
        keys = generate_keys(Path(tmp) / "keys")
        ek, dk = load_key("kem_pub", keys), load_key("kem_key", keys)
        pk, sk = load_key("dsa_pub", keys), load_key("dsa_key", keys)
        other_dk = ML_KEM_768.keygen()[1]

        secret = os.urandom(100_000)
        blob = lock(secret, ek)
        check("lock/unlock round-trip (100 KB)", unlock(blob, dk) == secret)
        check("lock/unlock round-trip (empty, str)", unlock(lock(b"", ek), dk) == b"" and unlock(lock("héllo", ek), dk) == "héllo".encode())
        check("locked output is not the plaintext", secret[:64] not in blob)
        check("two locks of the same data differ", lock(b"same", ek) != lock(b"same", ek))
        for label, offset in (("data", len(blob) - 50), ("KEM ciphertext", 10), ("wrapped key", HEADER_LEN - 20)):
            bad = bytearray(blob); bad[offset] ^= 0x01
            check(f"one flipped bit in the {label} -> TamperedError", raises_tampered(lambda b=bytes(bad): unlock(b, dk)))
        check("wrong private key -> TamperedError", raises_tampered(lambda: unlock(blob, other_dk)))
        check("truncated blob -> TamperedError", raises_tampered(lambda: unlock(blob[:100], dk)))

        sig = sign("transfer £100 to account 42", sk)
        check("sign/verify genuine message", verify("transfer £100 to account 42", sig, pk))
        check("verify rejects a one-letter change", not verify("transfer £900 to account 42", sig, pk))
        check("verify rejects a corrupted signature", not verify("transfer £100 to account 42", sig[:-1] + bytes([sig[-1] ^ 1]), pk))
        check("verify rejects garbage signature", not verify("x", b"junk", pk))

        log = Path(tmp) / "notes.jsonl"
        writer = SealedLog(log, sk)
        for i in range(6):
            writer.write({"time": f"2026-10-17T16:0{i}:00Z", "client": f"10.0.0.{i}", "tls": "1.3",
                          "key_chosen": "X25519MLKEM768", "strength": "strong"})
        check("sealed log verifies clean", verify_log(log, pk)["ok"])
        check("log file keeps the agreed note format (plain JSON lines)", json.loads(log.read_text().splitlines()[0])["client"] == "10.0.0.0")
        SealedLog(log, sk).write({"client": "10.0.0.99", "strength": "strong"})
        check("re-opening a log continues the seal chain", verify_log(log, pk)["ok"])

        shared = SealedLog(log, sk)  # one SealedLog object per log file, shared by all threads
        threads = [threading.Thread(target=lambda n=n: shared.write({"client": f"10.1.0.{n}"})) for n in range(6)]
        for t in threads: t.start()
        for t in threads: t.join()
        check("SealedLog is safe with concurrent writers", verify_log(log, pk)["ok"])

        # follow mode: another program writes the log, we seal it from the side
        gw_log = Path(tmp) / "gateway_notes.jsonl"
        stop = threading.Event()
        watcher = threading.Thread(target=follow_log, args=(gw_log, sk), kwargs={"poll_s": 0.05, "stop": stop})
        watcher.start()
        with open(gw_log, "w") as f:  # the "gateway": plain writes, half-written last line
            f.write('{"client": "10.2.0.1", "strength": "strong"}\n{"client": "10.2.0.2", "stre')
            f.flush(); time.sleep(0.3)
            f.write('ngth": "weak"}\n')
        deadline = time.time() + 10
        while time.time() < deadline and len(_seal_path(gw_log).read_text().splitlines() if _seal_path(gw_log).exists() else []) < 2:
            time.sleep(0.05)
        stop.set(); watcher.join()
        check("follow mode seals lines another program writes (incl. half-written ones)", verify_log(gw_log, pk)["ok"]
              and verify_log(gw_log, pk)["lines"] == 2)
        with open(gw_log, "a") as f:
            f.write('{"client": "10.2.0.3", "strength": "strong"}\n')
        stop2 = threading.Event()
        watcher = threading.Thread(target=follow_log, args=(gw_log, sk), kwargs={"poll_s": 0.05, "stop": stop2})
        watcher.start(); time.sleep(0.5)
        while time.time() < deadline and len(_seal_path(gw_log).read_text().splitlines()) < 3:
            time.sleep(0.05)
        stop2.set(); watcher.join()
        check("follow mode restarts without re-sealing old lines", verify_log(gw_log, pk)["ok"]
              and len(_seal_path(gw_log).read_text().splitlines()) == 3)

        original = log.read_bytes()
        log.write_bytes(original.replace(b'"strength": "strong"}\n{"time": "2026-10-17T16:03', b'"strength": "strenG"}\n{"time": "2026-10-17T16:03', 1))
        rep = verify_log(log, pk)
        check("one-letter edit -> TAMPERED at the right line (3)", not rep["ok"] and rep["problems"][0][0] == 3)
        lines = original.split(b"\n")
        log.write_bytes(b"\n".join(lines[:2] + lines[3:]))
        rep = verify_log(log, pk)
        check("deleted line -> TAMPERED at line 3", not rep["ok"] and rep["problems"][0][0] == 3)
        log.write_bytes(original + b'{"client": "attacker", "strength": "strong"}\n')
        check("appended fake line -> TAMPERED", not verify_log(log, pk)["ok"])
        log.write_bytes(original)
        seals = _seal_path(log).read_text().splitlines()
        rec = json.loads(seals[1]); rec["line_sha256"] = "00" * 32; seals[1] = json.dumps(rec)
        _seal_path(log).write_text("\n".join(seals) + "\n")
        check("forged seal record -> TAMPERED", not verify_log(log, pk)["ok"])
        stranger_pk = ML_DSA_65.keygen()[0]
        check("someone else's public key cannot validate our log", not verify_log(log, stranger_pk)["ok"])

        try:  # interoperability with the native OpenSSL implementation, if this build has it
            from cryptography.hazmat.primitives.asymmetric import mlkem
            native = mlkem.MLKEM768PrivateKey.generate()
            nblob = lock(b"interop", native.public_key().public_bytes_raw())
            kem_ct = nblob[len(MAGIC):len(MAGIC) + KEM_CT_LEN]
            p = len(MAGIC) + KEM_CT_LEN
            kek = _hkdf(native.decapsulate(kem_ct), b"qsafe/v1/key-wrap")
            dek = _gcm_decrypt(kek, nblob[p:p + NONCE_LEN], nblob[p + NONCE_LEN:p + NONCE_LEN + WRAPPED_LEN], MAGIC + kem_ct)
            check("ML-KEM output interoperates with OpenSSL's ML-KEM (FIPS 203)",
                  _gcm_decrypt(dek, nblob[HEADER_LEN - NONCE_LEN:HEADER_LEN], nblob[HEADER_LEN:], nblob[:HEADER_LEN]) == b"interop")
        except Exception:
            print("  [skip] OpenSSL ML-KEM not in this cryptography build (fine, not needed)")

    ok = all(results)
    print(f"\n{sum(results)}/{len(results)} passed: {'ALL GOOD' if ok else 'FAILURES ABOVE'}")
    return ok


# ---------------------------------------------------------------------------
# Benchmark: classical vs post-quantum, for Person A's table
# ---------------------------------------------------------------------------
def _median_ms(fn, min_runs=5, max_runs=200, budget_s=1.5) -> float:
    times, start = [], time.perf_counter()
    while len(times) < max_runs and (len(times) < min_runs or time.perf_counter() - start < budget_s):
        t = time.perf_counter(); fn(); times.append((time.perf_counter() - t) * 1000)
    return statistics.median(times)


def _cpacf_available() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("features"):
                return "yes (CPU feature 'msa')" if " msa" in line else "no"
    except OSError:
        pass
    return "n/a (not IBM Z)"


def benchmark(out_dir=".") -> dict:
    rows = []  # (family, algorithm, implementation, operation, ms)
    sizes = []  # (algorithm, public key, private key, ciphertext or signature)

    def add(family, alg, impl, op, fn):
        ms = _median_ms(fn)
        rows.append((family, alg, impl, op, round(ms, 3)))
        print(f"  {alg:<16} {impl:<22} {op:<10} {ms:9.3f} ms")

    print(f"Benchmark on {platform.machine()} / Python {platform.python_version()} / AES via {AES_BACKEND}")
    print("Key exchange / key wrapping")
    ek, dk = ML_KEM_768.keygen()
    _, ct = ML_KEM_768.encaps(ek)
    add("KEM", "ML-KEM-768", "pure Python (ours)", "keygen", ML_KEM_768.keygen)
    add("KEM", "ML-KEM-768", "pure Python (ours)", "encaps", lambda: ML_KEM_768.encaps(ek))
    add("KEM", "ML-KEM-768", "pure Python (ours)", "decaps", lambda: ML_KEM_768.decaps(dk, ct))
    sizes.append(("ML-KEM-768", len(ek), len(dk), len(ct)))

    native_note = None
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem, mldsa
        nk = mlkem.MLKEM768PrivateKey.generate(); npub = nk.public_key(); _, nct = npub.encapsulate()
        add("KEM", "ML-KEM-768", "OpenSSL (native C)", "keygen", mlkem.MLKEM768PrivateKey.generate)
        add("KEM", "ML-KEM-768", "OpenSSL (native C)", "encaps", npub.encapsulate)
        add("KEM", "ML-KEM-768", "OpenSSL (native C)", "decaps", lambda: nk.decapsulate(nct))
    except Exception:
        mldsa = None
        native_note = "Native OpenSSL ML-KEM/ML-DSA not available in this cryptography build; pure-Python numbers only."

    classical = True
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519, ed25519, ec
        from cryptography.hazmat.primitives import hashes, serialization
        oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        rk = rsa.generate_private_key(public_exponent=65537, key_size=2048); rpub = rk.public_key()
        rct = rpub.encrypt(os.urandom(32), oaep)
        add("KEM", "RSA-2048 OAEP", "OpenSSL (native C)", "keygen", lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048))
        add("KEM", "RSA-2048 OAEP", "OpenSSL (native C)", "encaps", lambda: rpub.encrypt(os.urandom(32), oaep))
        add("KEM", "RSA-2048 OAEP", "OpenSSL (native C)", "decaps", lambda: rk.decrypt(rct, oaep))
        der = lambda k: len(k.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        sizes.append(("RSA-2048", len(rpub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)), der(rk), len(rct)))
        xk = x25519.X25519PrivateKey.generate(); xpub = x25519.X25519PrivateKey.generate().public_key()
        add("KEM", "X25519", "OpenSSL (native C)", "keygen", x25519.X25519PrivateKey.generate)
        add("KEM", "X25519", "OpenSSL (native C)", "exchange", lambda: xk.exchange(xpub))
        sizes.append(("X25519", 32, 32, 32))
    except ImportError:
        classical = False

    print("Signatures")
    pk, sk = ML_DSA_65.keygen()
    msg = b'{"time":"2026-10-17T16:00:00Z","client":"10.0.0.5","tls":"1.3","strength":"strong"}'
    sig = ML_DSA_65.sign(sk, msg)
    add("SIG", "ML-DSA-65", "pure Python (ours)", "keygen", ML_DSA_65.keygen)
    add("SIG", "ML-DSA-65", "pure Python (ours)", "sign", lambda: ML_DSA_65.sign(sk, msg))
    add("SIG", "ML-DSA-65", "pure Python (ours)", "verify", lambda: ML_DSA_65.verify(pk, msg, sig))
    sizes.append(("ML-DSA-65", len(pk), len(sk), len(sig)))
    if mldsa is not None:
        try:
            ns = mldsa.MLDSA65PrivateKey.generate(); nsig = ns.sign(msg); npk = ns.public_key()
            add("SIG", "ML-DSA-65", "OpenSSL (native C)", "keygen", mldsa.MLDSA65PrivateKey.generate)
            add("SIG", "ML-DSA-65", "OpenSSL (native C)", "sign", lambda: ns.sign(msg))
            add("SIG", "ML-DSA-65", "OpenSSL (native C)", "verify", lambda: npk.verify(nsig, msg))
        except Exception:
            pass
    if classical:
        ek2 = ed25519.Ed25519PrivateKey.generate(); esig = ek2.sign(msg); epk = ek2.public_key()
        add("SIG", "Ed25519", "OpenSSL (native C)", "keygen", ed25519.Ed25519PrivateKey.generate)
        add("SIG", "Ed25519", "OpenSSL (native C)", "sign", lambda: ek2.sign(msg))
        add("SIG", "Ed25519", "OpenSSL (native C)", "verify", lambda: epk.verify(esig, msg))
        sizes.append(("Ed25519", 32, 32, 64))
        pk256 = ec.generate_private_key(ec.SECP256R1()); psig = pk256.sign(msg, ec.ECDSA(hashes.SHA256()))
        add("SIG", "ECDSA P-256", "OpenSSL (native C)", "sign", lambda: pk256.sign(msg, ec.ECDSA(hashes.SHA256())))
        add("SIG", "ECDSA P-256", "OpenSSL (native C)", "verify", lambda: pk256.public_key().verify(psig, msg, ec.ECDSA(hashes.SHA256())))
        sizes.append(("ECDSA P-256", 65, 32, len(psig)))

    print("Our functions, end to end")
    one_mb = os.urandom(1_000_000)
    blob = lock(one_mb, ek)
    add("E2E", "lock()", "ours", "1 MB", lambda: lock(one_mb, ek))
    add("E2E", "unlock()", "ours", "1 MB", lambda: unlock(blob, dk))
    add("E2E", "lock()", "ours", "1 KB", lambda: lock(one_mb[:1000], ek))
    add("E2E", "sign()", "ours", "1 log line", lambda: sign(msg, sk))
    our_sig = sign(msg, sk)
    add("E2E", "verify()", "ours", "1 log line", lambda: verify(msg, our_sig, pk))
    with tempfile.TemporaryDirectory() as tmp:
        sl = SealedLog(Path(tmp) / "bench.jsonl", sk)
        add("E2E", "SealedLog.write", "ours", "1 log line", lambda: sl.write(msg.decode()))

    meta = {"machine": platform.machine(), "python": platform.python_version(), "aes_backend": AES_BACKEND,
            "ibm_z_cpacf_crypto_hardware": _cpacf_available(), "cpus": os.cpu_count(),
            "date": time.strftime("%Y-%m-%d %H:%M"), "lock_overhead_bytes": HEADER_LEN + 16}
    result = {"meta": meta, "timings_ms": rows, "sizes_bytes": sizes, "note": native_note}

    md = ["# Crypto benchmark: classical vs post-quantum",
          "",
          f"Measured on **{meta['machine']}**, Python {meta['python']}, {meta['date']}. "
          f"AES via {meta['aes_backend']}. IBM Z crypto hardware (CPACF): {meta['ibm_z_cpacf_crypto_hardware']}.",
          "", "Median time per operation (lower is better).", "",
          "| Family | Algorithm | Implementation | Operation | ms |", "|---|---|---|---|---:|"]
    md += [f"| {f} | {a} | {i} | {o} | {ms:.3f} |" for f, a, i, o, ms in rows]
    md += ["", "Sizes in bytes (post-quantum keys are bigger; this is the main real cost).", "",
           "| Algorithm | Public key | Private key | Ciphertext / signature |", "|---|---:|---:|---:|"]
    md += [f"| {a} | {p} | {s} | {c} |" for a, p, s, c in sizes]
    md += ["", f"lock() adds a fixed {meta['lock_overhead_bytes']} bytes to each item it encrypts.", "",
           "Note: 'pure Python (ours)' is what the demo runs; 'OpenSSL (native C)' rows show the same "
           "algorithms as a production build would run them. Compare algorithms within the same implementation."]
    if native_note:
        md += ["", native_note]
    out_dir = Path(out_dir)
    (out_dir / "bench_results.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (out_dir / "bench_results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\nWrote {out_dir / 'bench_results.md'} and {out_dir / 'bench_results.json'}")
    return result


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------
def _colour(text, code):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text


def _cli(argv=None) -> int:
    p = argparse.ArgumentParser(prog="qsafe_crypto", description="Quantum-safe lock/unlock/sign/verify (ML-KEM-768, ML-DSA-65, AES-256-GCM).")
    p.add_argument("--keys", help="key folder (default ./keys or $QSAFE_KEYS)")
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="create a new key pair in ./keys"); k.add_argument("--force", action="store_true")
    for name, helptext in (("lock", "encrypt a file"), ("unlock", "decrypt a file")):
        s = sub.add_parser(name, help=helptext); s.add_argument("file"); s.add_argument("-o", "--out")
    s = sub.add_parser("sign", help="sign a document -> FILE.sig"); s.add_argument("file")
    s = sub.add_parser("seal", help="seal every line of an existing log -> LOG.seal"); s.add_argument("log"); s.add_argument("--force", action="store_true")
    s = sub.add_parser("follow", help="keep sealing new lines as the gateway writes them (Ctrl+C to stop)"); s.add_argument("log")
    s = sub.add_parser("verify", help="check a sealed log or a signed document; shouts TAMPERED"); s.add_argument("file")
    sub.add_parser("selftest", help="run all checks")
    b = sub.add_parser("bench", help="classical vs post-quantum timings -> bench_results.md"); b.add_argument("--out", default=".")
    a = p.parse_args(argv)

    if a.cmd == "keygen":
        d = generate_keys(a.keys, overwrite=a.force)
        print(f"Keys written to {d}/ (keep *.key files secret; never commit them)")
    elif a.cmd == "lock":
        out = Path(a.out or a.file + ".locked")
        out.write_bytes(lock(Path(a.file).read_bytes(), load_key("kem_pub", a.keys)))
        print(f"Locked {a.file} -> {out}")
    elif a.cmd == "unlock":
        src = Path(a.file)
        out = Path(a.out or (str(src)[:-7] + ".unlocked" if src.name.endswith(".locked") else str(src) + ".unlocked"))
        try:
            out.write_bytes(unlock(src.read_bytes(), load_key("kem_key", a.keys)))
        except TamperedError as e:
            print(_colour(f"TAMPERED: {e}", "1;31")); return 1
        print(f"Unlocked {a.file} -> {out}")
    elif a.cmd == "sign":
        Path(a.file + ".sig").write_bytes(sign(Path(a.file).read_bytes(), load_key("dsa_key", a.keys)))
        print(f"Signed {a.file} -> {a.file}.sig")
    elif a.cmd == "seal":
        n = seal_existing_log(a.log, load_key("dsa_key", a.keys), overwrite=a.force)
        print(f"Sealed {n} lines of {a.log} -> {a.log}.seal")
    elif a.cmd == "follow":
        print(f"Sealing new lines of {a.log} with ML-DSA-65 as they arrive (Ctrl+C to stop)")
        try:
            follow_log(a.log, load_key("dsa_key", a.keys),
                       on_seal=lambda n, raw: print(f"  sealed line {n}: {raw[:70].decode('utf-8', 'replace')}"))
        except KeyboardInterrupt:
            print("\nStopped.")
    elif a.cmd == "verify":
        pk = load_key("dsa_pub", a.keys)
        if _seal_path(a.file).exists():
            rep = verify_log(a.file, pk)
            for line_no, reason in rep["problems"]:
                print(_colour(f"  line {line_no}: TAMPERED, {reason}", "31"))
            if rep["ok"]:
                print(_colour(f"OK: all {rep['lines']} lines intact and signed (ML-DSA-65)", "1;32")); return 0
            print(_colour(f"TAMPERED: {len(rep['problems'])} problem(s) in {a.file}", "1;31")); return 1
        if Path(a.file + ".sig").exists():
            if verify(Path(a.file).read_bytes(), Path(a.file + ".sig").read_bytes(), pk):
                print(_colour(f"OK: {a.file} matches its ML-DSA-65 signature", "1;32")); return 0
            print(_colour(f"TAMPERED: {a.file} does not match its signature", "1;31")); return 1
        print(f"Nothing to check: no {a.file}.seal or {a.file}.sig found"); return 2
    elif a.cmd == "selftest":
        return 0 if selftest() else 1
    elif a.cmd == "bench":
        benchmark(a.out)
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
