# Crypto layer (Person B): `qsafe_crypto.py`

Post-quantum encryption and tamper-evident logs for the Quantum-Safe Gateway.

| What | Algorithm | Standard |
|---|---|---|
| Encrypt data at rest | AES-256-GCM, data key wrapped with **ML-KEM-768** | NIST FIPS 203 |
| Sign logs and documents | **ML-DSA-65** | NIST FIPS 204 |

## Setup (once)

```bash
pip install -r requirements-crypto.txt
python qsafe_crypto.py keygen      # creates keys/ ; NEVER commit keys/ (it's in .gitignore)
python qsafe_crypto.py selftest    # should end with "ALL GOOD"
```

## The four functions (Python)

```python
from qsafe_crypto import lock, unlock, sign, verify, TamperedError

blob = lock(b"customer records")         # -> bytes, safe to store anywhere
data = unlock(blob)                      # -> original bytes; raises TamperedError if 1 byte changed

sig = sign("some message")               # -> 3309-byte ML-DSA-65 signature
ok  = verify("some message", sig)        # -> True / False
```

Keys are read from `./keys` (or the `QSAFE_KEYS` folder). You can also pass key bytes directly:
`lock(data, public_key=...)`, `unlock(blob, private_key=...)`.

## For A (gateway): sealing the connection notes

Pick one:

1. **Gateway in any language (recommended):** keep writing `notes.jsonl` exactly as agreed, one JSON note per line, and run this next to it:
   ```bash
   python qsafe_crypto.py follow notes.jsonl
   ```
   It seals each new line as it appears. Your gateway is never slowed down by signing.
2. **Gateway in Python:** write through the sealed log instead of `open().write()`:
   ```python
   from qsafe_crypto import SealedLog
   notes = SealedLog("notes.jsonl")      # create once, share between threads
   notes.write({"time": ..., "client": ..., "tls_version": ..., "strength": "strong"})
   ```
   Note: this signs inline (about 40 ms per line in pure Python).

## For D (tripwire): nothing changes

`notes.jsonl` keeps the agreed format. The seals live in a separate file, `notes.jsonl.seal`, which you can ignore.
Optional dashboard tile:
```python
from qsafe_crypto import verify_log
report = verify_log("notes.jsonl")   # {"ok": bool, "lines": n, "problems": [(line_no, reason), ...]}
```

## For C and E: demo commands

```bash
python qsafe_crypto.py lock bank_records.csv          # -> bank_records.csv.locked (gibberish)
python qsafe_crypto.py unlock bank_records.csv.locked # -> bank_records.csv.unlocked

python qsafe_crypto.py verify notes.jsonl             # green OK
sed -i 's/"weak"/"strong"/' notes.jsonl               # attacker tries to hide a weak connection
python qsafe_crypto.py verify notes.jsonl             # red TAMPERED, with the exact line number

python qsafe_crypto.py sign report.pdf                # -> report.pdf.sig
python qsafe_crypto.py verify report.pdf
```

What the log check catches: one changed character, a deleted line, an inserted or appended line, reordered lines, and forged seals. It does this because every line's hash is chained to the one before it, and each link is signed with ML-DSA-65.

## For A's benchmark table

```bash
python qsafe_crypto.py bench    # -> bench_results.md + bench_results.json
```
Run it **on the LinuxONE VM** so the table says `s390x`. It times ML-KEM vs RSA-2048 and X25519, ML-DSA vs Ed25519 and ECDSA, and our own functions, plus key and signature sizes.

## Honest limitations (say these if judges ask)

- ML-KEM and ML-DSA come from pure-Python libraries (kyber-py, dilithium-py). That makes them portable (nothing to compile on s390x) but slow, and they are not hardened against timing side-channels. Production would use the same algorithms through OpenSSL 3.5+ or liboqs. The output is standard: `selftest` checks interoperability with OpenSSL's ML-KEM when it is available.
- Private keys sit unencrypted in `keys/` for the demo. Production would keep them in an HSM (on IBM Z: the Crypto Express cards).
- The log check proves lines weren't changed. It can't detect someone deleting **both** the log and seal files from the end, so ship seals off-box regularly.

## Open-source libraries used (list these in the submission)

- kyber-py: https://github.com/GiacomoPope/kyber-py
- dilithium-py: https://github.com/GiacomoPope/dilithium-py
- cryptography: https://github.com/pyca/cryptography
- pycryptodome (fallback only): https://github.com/Legrandin/pycryptodome
