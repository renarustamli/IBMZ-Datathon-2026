# Gateway benchmarks

Measured 2026-10-17 15:58 UTC on `entitiesdatathon` (linux/s390x, 3 CPUs, go1.27.2). Client, gateway (legacy mode) and backend all on the same host over loopback, so latency is CPU cost plus loopback, not real network.

## Handshake latency (500 handshakes per mode, modes alternated, 20 warm-ups each discarded)

| Key exchange | mean (ms) | p50 (ms) | p95 (ms) | client bytes sent | client bytes received | throughput (MB/s) |
|---|---|---|---|---|---|---|
| classical X25519 | 0.702 | 0.611 | 0.950 | 320 | 743 | 2371.1 |
| hybrid X25519MLKEM768 | 1.033 | 0.943 | 1.273 | 1504 | 1832 | 2224.5 |

Throughput: mean of 5 downloads of 100 MB each through the gateway. The bulk cipher is TLS_AES_128_GCM_SHA256 in both modes (Go picks it; the key exchange only changes the handshake), so throughput should be about the same.

## Key sizes (read from crypto/mlkem and crypto/ecdh)

| Item | bytes |
|---|---|
| X25519 public key | 32 |
| ML-KEM-768 encapsulation key | 1184 |
| ML-KEM-768 ciphertext | 1088 |
| Hybrid client key share (ML-KEM ek + X25519) | 1216 |
| Hybrid server key share (ML-KEM ct + X25519) | 1120 |

## Key-exchange primitives (mean of 2000 ops, microseconds)

| Operation | µs |
|---|---|
| X25519 keygen | 90.1 |
| X25519 shared secret | 89.7 |
| ML-KEM-768 keygen | 82.8 |
| ML-KEM-768 encapsulate | 87.2 |
| ML-KEM-768 decapsulate | 122.3 |

Raw per-handshake data: `handshakes.csv`. Summary: `results.csv`. Certificates are classical ECDSA in both modes.
