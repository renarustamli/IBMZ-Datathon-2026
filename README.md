# Quantum-Safe Gateway for Legacy Systems

> **[TEAM_NAME] — IBM Z Datathon 2026**
> Theme 2: AI Secured — *Powerful AI. Protected Data.*
> Event code: `SSF2026`

A drop-in security layer that makes an old, vulnerable service **quantum-safe without rewriting it** — defending against "harvest now, decrypt later" attacks, running and benchmarked on **IBM LinuxONE (s390x)**.

---

## The Problem

Attackers can record encrypted traffic **today** and decrypt it years later, once quantum computers mature — the "harvest now, decrypt later" threat. RSA and elliptic-curve cryptography will not survive that transition. Any data that must stay secret for 10+ years (financial records, health data, government archives) is **already at risk**, even though the break hasn't happened yet.

Rewriting every legacy system to be quantum-safe is slow, expensive, and often impossible. Organisations need protection *now*, without touching the old code.

## Our Solution

A reverse-proxy **gateway** that sits in front of an existing service and transparently upgrades its security to post-quantum standards:

1. **Hybrid post-quantum TLS** — X25519 + ML-KEM on the client side
2. **Data at rest** — AES-256-GCM, with keys wrapped by ML-KEM
3. **Integrity** — audit logs and documents signed with ML-DSA
4. **AI downgrade/anomaly detector** — an ML model that learns normal handshake patterns and flags downgrade attacks (someone forcing a fallback to weak classical crypto) in real time
5. **LinuxONE benchmarks** — classical vs post-quantum: handshake latency, throughput, key/ciphertext sizes

The legacy service is never modified. The gateway does all the work.

## Why IBM Z / LinuxONE

<!-- Fill this in with your actual evidence + screenshots — this is a top-scoring criterion -->

- Post-quantum cryptography benchmarked on **s390x**, the architecture that runs the majority of the world's financial transactions
- Confidential Computing / pervasive encryption: sensitive data stays protected [describe what you used]
- Containerised and isolated deployment on LinuxONE [screenshot]
- [Add: VM dashboard screenshot, running instance, model output]

## Demo

A simulated **harvest-now-decrypt-later** attacker:

- **Legacy service:** a deliberately weak RSA key (scaled down for the demo) is factored in seconds → captured data is exposed.
- **Through our gateway:** the same captured bytes stay unreadable.
- **Live:** a downgrade attempt fires the detector and turns the dashboard red.

> Note: the demo uses an intentionally small key to illustrate the attack in seconds. This is a scaled-down illustration, not a break of production-grade RSA.

## Architecture

<!-- Add your flowchart / diagram here (optional submission, worth including) -->

```
[ Client ] --hybrid PQC-TLS--> [ GATEWAY ] --> [ Legacy Service ]
                                   |
                                   +--> AES-256-GCM at rest (ML-KEM-wrapped keys)
                                   +--> ML-DSA signed audit logs
                                   +--> connection logs --> [ AI Detector ] --> [ Dashboard ]
```

## Tech Stack

- **Language(s):** [e.g. Go 1.24+ for the gateway/PQC, Python for the detector]
- **Post-quantum crypto:** [ML-KEM, ML-DSA — via which library]
- **AI/ML:** [model type, framework]
- **Platform:** IBM LinuxONE Community Cloud (s390x)
- [add the rest as you go]

## Getting Started

```bash
# Clone
git clone https://github.com/[USER]/IBMZ-Datathon-2026.git
cd IBMZ-Datathon-2026

# [Add real setup + run steps here]
```

## Repository Structure

```
/gateway        # reverse proxy + hybrid PQC-TLS (Person A)
/crypto         # lock/unlock/sign/verify functions (Person B)
/demo           # legacy service + attacker simulation (Person C)
/detector       # AI tripwire + dashboard (Person D)
/benchmarks     # classical vs PQC results
```
<!-- Adjust to match what you actually build -->

## Open-Source Libraries & Resources

<!-- REQUIRED for submission — list every open-source lib, framework, API, and dataset with links -->

- [library] — [link] — [what it's used for]
- [library] — [link] — [what it's used for]

## Team

| Role | Area |
|------|------|
| [Name] | Gateway + hardware + benchmarks |
| [Name] | Crypto functions (encrypt / decrypt / sign / verify) |
| [Name] | Legacy service + attacker simulation |
| Rana | AI tripwire + dashboard |
| [Name] | Pitch video + submission |

## License

[Add one if you want — MIT is a safe default for a hackathon]

---

*Built from scratch during the IBM Z Datathon 2026 hacking window (Oct 17–18).*
