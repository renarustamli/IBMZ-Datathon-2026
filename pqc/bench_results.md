# Crypto benchmark: classical vs post-quantum

Measured on **s390x**, Python 3.12.3, 2026-10-17 15:47. AES via cryptography (OpenSSL). IBM Z crypto hardware (CPACF): yes (CPU feature 'msa').

Median time per operation (lower is better).

| Family | Algorithm | Implementation | Operation | ms |
|---|---|---|---|---:|
| KEM | ML-KEM-768 | pure Python (ours) | keygen | 3.074 |
| KEM | ML-KEM-768 | pure Python (ours) | encaps | 4.194 |
| KEM | ML-KEM-768 | pure Python (ours) | decaps | 5.680 |
| KEM | RSA-2048 OAEP | OpenSSL (native C) | keygen | 186.879 |
| KEM | RSA-2048 OAEP | OpenSSL (native C) | encaps | 0.064 |
| KEM | RSA-2048 OAEP | OpenSSL (native C) | decaps | 1.952 |
| KEM | X25519 | OpenSSL (native C) | keygen | 0.025 |
| KEM | X25519 | OpenSSL (native C) | exchange | 0.023 |
| SIG | ML-DSA-65 | pure Python (ours) | keygen | 9.235 |
| SIG | ML-DSA-65 | pure Python (ours) | sign | 39.084 |
| SIG | ML-DSA-65 | pure Python (ours) | verify | 10.588 |
| SIG | Ed25519 | OpenSSL (native C) | keygen | 0.035 |
| SIG | Ed25519 | OpenSSL (native C) | sign | 0.035 |
| SIG | Ed25519 | OpenSSL (native C) | verify | 0.049 |
| SIG | ECDSA P-256 | OpenSSL (native C) | sign | 0.023 |
| SIG | ECDSA P-256 | OpenSSL (native C) | verify | 0.071 |
| E2E | lock() | ours | 1 MB | 4.411 |
| E2E | unlock() | ours | 1 MB | 6.452 |
| E2E | lock() | ours | 1 KB | 4.249 |
| E2E | sign() | ours | 1 log line | 35.358 |
| E2E | verify() | ours | 1 log line | 10.655 |
| E2E | SealedLog.write | ours | 1 log line | 47.052 |

Sizes in bytes (post-quantum keys are bigger; this is the main real cost).

| Algorithm | Public key | Private key | Ciphertext / signature |
|---|---:|---:|---:|
| ML-KEM-768 | 1184 | 2400 | 1088 |
| RSA-2048 | 294 | 1216 | 256 |
| X25519 | 32 | 32 | 32 |
| ML-DSA-65 | 1952 | 4032 | 3309 |
| Ed25519 | 32 | 32 | 64 |
| ECDSA P-256 | 65 | 32 | 72 |

lock() adds a fixed 1180 bytes to each item it encrypts.

Note: 'pure Python (ours)' is what the demo runs; 'OpenSSL (native C)' rows show the same algorithms as a production build would run them. Compare algorithms within the same implementation.

Native OpenSSL ML-KEM/ML-DSA not available in this cryptography build; pure-Python numbers only.
