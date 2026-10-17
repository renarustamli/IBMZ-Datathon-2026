# CLAUDE.md — context for Claude Code

Read this first. It briefs you (a fresh Claude session in VS Code) on this project so you can pick up without the original chat. Human-facing detail lives in the files pointed to below — read them before writing code that touches those areas.

## What this project is

**Quantum-Safe Gateway for Legacy Systems** — IBM Z Datathon 2026, Theme 2 (AI Secured).

A drop-in reverse-proxy gateway that makes an old, vulnerable service quantum-safe without rewriting it. Defends against "harvest now, decrypt later": attackers record encrypted data today and decrypt it once quantum computers mature. The gateway adds hybrid post-quantum TLS, encrypts data at rest, signs logs, and an AI detector flags downgrade attacks. Everything runs and is benchmarked on IBM LinuxONE (s390x) — that is the "why this platform" story.

Full project plan: **`NOTES.md`**. Public-facing overview: **`README.md`**.

## The one contract that matters

**`INTERFACES.md`** defines the exact points where team members' code touches. Do not invent your own formats — match these. The key one is the **connection note** (§1): the gateway writes one JSON object per line to `logs/connections.jsonl`, and the detector reads it. Fields: `ts, client_id, tls_version, cipher_suite, key_groups_offered, key_group_chosen, strong_or_weak`. A downgrade = a client that offered a post-quantum key group before, now offering only classical groups.

If you change a shared format, update `INTERFACES.md` in the same commit and say so — other people build against it.

## Team split (so you know whose code is whose)

- **A** — gateway + hybrid PQC-TLS + benchmarks (writes the connection notes)
- **B** — crypto functions: `lock / unlock / sign / verify`
- **C** — weak legacy service + attacker + downgrade trick + sample traffic for D
- **D** — the detector + dashboard (**this is the part in `/detector`, owned by Rena**)
- **E** — pitch video + submission

## What's built: `/detector` (role D, Rena)

`pip install -r detector/requirements.txt`, then from `detector/`:
`python generate_traffic.py` → `python detector.py` (self-test) → `python dashboard.py` (http://localhost:5000).
Demo without the gateway: `python generate_traffic.py --live` in a second terminal (appends to `logs/connections.jsonl`, one attack every ~20 s).

- **`schema.py`** — the §1 field list plus the value vocabulary (PQC vs classical group names, cipher strength, ts parsing). INTERFACES.md was not available when this was written, so the value formats (`"TLSv1.3"`, `"X25519MLKEM768"`, `"strong"/"weak"`, ISO-8601 `ts`) are assumptions — reconcile them here only.
- **`generate_traffic.py`** — synthetic notes: `logs/normal_traffic.jsonl` (48 h, training), `logs/attack_traffic.jsonl` + `logs/attack_labels.json` (ground truth, not part of the schema). Attack types: `pqc_strip` (rule target), and `forced_classical`, `cipher_downgrade`, `burst`, `new_scanner` (model targets).
- **`detector.py`** — `Detector().train(normal_notes)`, `check(note) -> {alert, by: "rule"|"model"|None, reason, score}`. Layer 1: downgrade rule. Layer 2: kNN novelty detector (scaled features, threshold = 99.9th percentile of training distances) with per-alert attribution for the reason text. IsolationForest was tried and dropped: it missed every attack except the scanner, because the key deviations are values never seen in training.
- **`dashboard.py`** + `templates/dashboard.html` — tails `LOG_FILE` (default `logs/connections.jsonl`, handles truncation), red banner while any of the last 20 notes alerted.

Self-test result: rule 8/8 pqc_strip; model 8/8 forced_classical, 8/8 cipher_downgrade, 91/91 new_scanner, 239/255 burst notes (first notes of each burst are indistinguishable by design); 0.40% false positives on normal notes (3 of 4 are the burst victim's own traffic during the burst).

Caveats: `conn_per_min` is absolute, so a demo script that hammers the gateway from one client in a tight loop will (correctly) look like a burst — pace demo traffic. A `prior_downgrades` feature was tried and removed: it is 0 in all normal traffic, so it kept a client red forever after one downgrade; it now appears only as context in the reason text.

Next / stretch (boosts the AI Innovation score): a GenAI plain-English explanation per flag; retrain on C's real sample traffic once it lands.

## Conventions

- Keep the connection-note schema identical everywhere — it's the integration seam.
- Don't rewrite another role's folder (`/gateway`, `/crypto`, `/demo`) without coordinating.
- The RSA-break in the demo uses a deliberately tiny key — always label it as a scaled-down illustration, never a real break of production RSA.
- Rule: all project code must be written during the hackathon window (Oct 17–18). Open-source libraries are fine; list them in `README.md`.
