# Gateway (Person A)

A TLS 1.3 reverse proxy that sits in front of a legacy TCP service. Clients connect to the gateway with **hybrid post-quantum key exchange** (X25519 + ML-KEM-768, the `X25519MLKEM768` group). The gateway then forwards the decrypted bytes to the legacy service unchanged. The legacy service is not modified.

Each connection attempt adds one line to a connection-note log. D's detector reads that log.

Runs natively on IBM LinuxONE (s390x, Ubuntu 24.04) and is built with Go 1.27.

## What is post-quantum here

Two independent parts of the TLS handshake can each be classical or post-quantum:

| Handshake part | Classical | Post-quantum (this gateway) | Quantum threat it blocks |
|---|---|---|---|
| Key exchange | X25519 | **X25519 + ML-KEM-768** (hybrid) | Shor factoring recorded traffic ("harvest now, decrypt later") |
| Certificate signature | ECDSA P-256 | **ML-DSA-65** (FIPS 204), via `gencert -pq` | Shor forging the server's identity |
| Session cipher | AES-128-GCM | AES-128-GCM (not configurable, see limitations) | Grover (halves symmetric strength) |

Key exchange and authentication are both post-quantum. The symmetric cipher is chosen by Go and can't be changed (see limitations).

## Build and run

```bash
cd gateway
go build -o gateway .
go build -o testclient/testclient ./testclient
go build -o gencert/gencert ./gencert

# demo certificate (never committed). Pick one:
./gencert/gencert -pq        # ML-DSA-65 post-quantum certificate (recommended)
./gencert/gencert            # classical ECDSA P-256, for comparison

./gateway -mode strict                     # hybrid PQ key exchange only
./gateway -mode legacy                     # also accepts classical X25519 (logged as weak)
```

`gencert` uses only the Go standard library (`crypto/mldsa`, `crypto/x509`). `test.sh` builds a post-quantum cert automatically if none exists.

End-to-end test (starts a dummy backend on :9000 and the gateway, then connects one hybrid client and one classical client):

```bash
./test.sh          # strict: alice-laptop connects (strong), mallory-laptop is refused
./test.sh legacy   # legacy: both connect, mallory-laptop is logged as weak
```

### Docker (native s390x on LinuxONE)

The image is a multi-stage build. The final image is `scratch` with only `/gateway` and `/testclient` (about 9 MB), and no keys inside. `cert.pem`, `key.pem` and `logs/` are mounted at run time.

```bash
cd gateway                                # cert.pem and key.pem must be here
docker compose up -d --build              # strict mode, gateway + dummy backend
MODE=legacy docker compose up -d          # switch to legacy mode
./testclient/testclient -id alice-laptop  # test from the host
docker compose down
```

### Tunnel for clients without hybrid TLS

`testclient -local 127.0.0.1:9100 -id alice-laptop` listens for plain TCP on 9100 and carries each connection to the gateway over hybrid TLS. A client that can't do ML-KEM itself (e.g. Python with OpenSSL 3.0) connects to 9100 unchanged. Add `-classical` to simulate a downgraded client.

Add `-record <dir>` to save each connection's **encrypted client-to-gateway bytes** as `session_NNN.json`. The format is the same as the legacy server's recordings, so the attacker tool can read both. This is what a "harvest now, decrypt later" eavesdropper on the network would get. Tested on LinuxONE: the attacker cracked 3 of 3 direct recordings, and 0 of 3 wire recordings through the gateway ("no RSA public key in this recording").

Limits of what this shows:
- The SNI client ID (e.g. `alice-laptop`) is visible in the recorded ClientHello. SNI is not encrypted.
- The toy attacker only factors RSA. A failure here means the toy-RSA exchange no longer crosses the network. It does not test ML-KEM's strength.
- Behind the gateway, the legacy server's own recordings are still crackable, because the gateway-to-backend leg is plaintext loopback on the same host.

### Modes

| Mode | Accepted key exchange | Classical-only client |
|---|---|---|
| `strict` | `X25519MLKEM768` | handshake refused, note written with `key_chosen: "rejected"` |
| `legacy` | `X25519MLKEM768`, then `X25519` | connected, note written with `strength: "weak"` |

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `-mode` | `strict` | `strict` or `legacy` (see above) |
| `-listen` | `:8443` | address the gateway listens on |
| `-backend` | `127.0.0.1:9000` | legacy service address (raw TCP, forwarded unchanged) |
| `-notes` | `logs/connections.jsonl` | connection-note file (appended) |
| `-cert` / `-key` | `cert.pem` / `key.pem` | TLS certificate and private key |

Test client flags: `-addr` (default `localhost:8443`), `-classical` (offer only X25519), `-id` (client ID).

### Client ID (SNI)

The client ID comes from the TLS **server name (SNI)** that the client sends, e.g. `testclient -id alice-laptop`. Use letters, digits and hyphens only. Those are valid hostname characters that every TLS client will send. Go happens to accept underscores too, but other clients may not.

- If `-id` is empty, the Go client sends the host part of `-addr` instead (e.g. `localhost`).
- If no SNI is sent at all (for example, when connecting to an IP address), `client_id` is `"unknown"`.

The client ID is a label chosen by the client. It does not authenticate anyone.

## Connection-note format (FROZEN)

D's detector depends on this format, so fields are never renamed or removed. Each line of `logs/connections.jsonl` is one JSON object:

| Field | Example | Notes |
|---|---|---|
| `time` | `"2026-10-17T15:46:22Z"` | UTC, RFC 3339 |
| `client` | `"127.0.0.1:40194"` | remote IP:port |
| `client_id` | `"alice-laptop"` | from SNI |
| `tls_version` | `"TLS 1.3"` | `"none"` if the handshake failed |
| `cipher` | `"TLS_AES_128_GCM_SHA256"` | `"none"` if the handshake failed |
| `keys_offered` | `["X25519MLKEM768","other-4587","other-4589","X25519","P-256","P-384","P-521"]` | groups in the client's ClientHello |
| `key_chosen` | `"X25519MLKEM768"` | `"rejected"` if the handshake failed |
| `strength` | `"strong"` / `"weak"` | `strong` only when `X25519MLKEM768` was negotiated |

```json
{"time":"2026-10-17T15:53:16Z","client":"127.0.0.1:50038","client_id":"mallory-laptop","tls_version":"none","cipher":"none","keys_offered":["X25519"],"key_chosen":"rejected","strength":"weak"}
```

## Benchmarks

See [`bench/benchmarks.md`](bench/benchmarks.md) (raw data in `bench/handshakes.csv` and `bench/results.csv`). The benchmark runs a separate gateway on port 8444 with its own log, so it never writes to `logs/connections.jsonl`:

```bash
./gateway -mode legacy -listen 127.0.0.1:8444 -backend 127.0.0.1:9100 -notes logs/bench.jsonl &
go run ./bench -addr 127.0.0.1:8444 -n 500
```

## Honest limitations

- **The session cipher is AES-128-GCM** (`TLS_AES_128_GCM_SHA256`). Go's own docs say "TLS 1.3 ciphersuites are not configurable", so we cannot select AES-256 with the standard library, and rule 5 forbids writing our own crypto. Grover's algorithm roughly halves symmetric strength, which leaves AES-128 at about 64-bit quantum security in theory. That is still considered impractical to attack, but it is not AES-256.
- **ML-KEM and ML-DSA are young standards.** They are NIST standards (FIPS 203 and 204), but far less battle-tested than RSA/ECC. The hybrid key exchange keeps X25519 alongside ML-KEM precisely so that if ML-KEM is ever broken, the classical half still protects the session. The certificate signature does not have that fallback.
- **The demo certificate is self-signed.** A real deployment needs a certificate authority that itself issues ML-DSA certificates; the quantum-safe-identity story is only as strong as that chain.
- **The "quantum attack" in the demo is a simulation.** It factors a deliberately tiny (64-bit) toy RSA key on a normal CPU. No quantum computer is involved, and real RSA-2048 is not broken.
- **Protection is against known attacks.** We do not claim the gateway is "unbreakable".
- **`other-4587` / `other-4589`** in `keys_offered` are group codes that Go's client offers and our name table does not cover. We have not verified what they are, so we do not label them as post-quantum.
- **Only the network leg is protected.** Traffic between the gateway and the backend is plaintext on the same host (loopback).
- **Legacy mode accepts classical key exchange** on purpose, for the downgrade demo and old clients. Use strict mode for real protection.

## Libraries

Only the Go standard library: `crypto/tls` (TLS 1.3 with hybrid `X25519MLKEM768`), `crypto/mlkem`, `crypto/mldsa` and `crypto/x509` (ML-DSA-65 certificate), `crypto/ecdh` (benchmark key sizes and timings), and `net`, `encoding/json`. We did not write any crypto ourselves.

ML-DSA-65 sizes (from `crypto/mldsa`): public key 1952 bytes, signature 3309 bytes; the self-signed cert PEM is about 7.5 KB, versus roughly 0.5 KB for ECDSA P-256. That is the cost of post-quantum authentication.

## Scope note

The attacker tooling in this repo only targets our own demo services on localhost or our own LinuxONE instance. Do not point it at anything else.
