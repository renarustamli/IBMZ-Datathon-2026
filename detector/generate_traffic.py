"""Synthetic connection notes in the INTERFACES.md §1 format.

Lets the detector be built and trained before C delivers real traffic. Same schema,
so C's files (or the gateway's logs/connections.jsonl) drop in unchanged.

  python generate_traffic.py          -> logs/normal_traffic.jsonl, logs/attack_traffic.jsonl,
                                         logs/attack_labels.json (ground truth, NOT part of the schema)
  python generate_traffic.py --live   -> appends real-time notes to logs/connections.jsonl,
                                         with an attack every ~20 s (stand-in for the gateway)
"""
import argparse
import json
import math
import os
import random
import time
from datetime import datetime, timedelta, timezone

from schema import format_ts, write_notes, FIELDS

HERE = os.path.dirname(os.path.abspath(__file__))
LOGS = os.path.join(HERE, "..", "logs")

ATTACK_TYPES = ["pqc_strip", "forced_classical", "cipher_downgrade", "burst", "new_scanner"]


def make_clients(rng):
    """Fixed client population: most are modern PQC-capable, some are legacy classical-only."""
    clients = []
    for i in range(35):
        clients.append({
            "id": f"10.0.1.{10 + i}",
            "kind": "modern",
            "tls": "TLSv1.3",
            "cipher": rng.choice(["TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384",
                                  "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"]),
            "groups": rng.choice([["X25519MLKEM768", "x25519", "secp256r1"],
                                  ["X25519MLKEM768", "x25519", "secp256r1", "secp384r1"]]),
            "rate": rng.uniform(2, 12),  # connections per hour at peak
        })
    for i in range(10):
        clients.append({
            "id": f"10.0.2.{10 + i}",
            "kind": "legacy",
            "tls": "TLSv1.2",
            "cipher": rng.choice(["ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256"]),
            "groups": ["x25519", "secp256r1"],
            "rate": rng.uniform(2, 8),
        })
    for i in range(3):  # chatty service accounts (health checks, batch jobs)
        clients.append({
            "id": f"10.0.3.{10 + i}",
            "kind": "modern",
            "tls": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "groups": ["X25519MLKEM768", "x25519"],
            "rate": rng.uniform(40, 90),
        })
    return clients


def normal_note(c, ts):
    chosen = c["groups"][0]
    return {
        "ts": format_ts(ts),
        "client_id": c["id"],
        "tls_version": c["tls"],
        "cipher_suite": c["cipher"],
        "key_groups_offered": list(c["groups"]),
        "key_group_chosen": chosen,
        "strong_or_weak": "strong" if "MLKEM" in chosen else "weak",
    }


def diurnal(ts):
    """Traffic peaks mid-afternoon UTC; night is ~30% of peak."""
    h = ts.hour + ts.minute / 60
    return 0.65 + 0.35 * math.cos((h - 14) / 24 * 2 * math.pi)


def gen_normal(rng, clients, start, hours):
    notes = []
    end = start + timedelta(hours=hours)
    for c in clients:
        t = start + timedelta(seconds=rng.uniform(0, 3600 / c["rate"]))
        while t < end:
            if rng.random() < diurnal(t):  # thinning -> time-of-day profile
                notes.append(normal_note(c, t))
            t += timedelta(seconds=rng.expovariate(c["rate"] / 3600))
    notes.sort(key=lambda n: n["ts"])
    return notes


def gen_attack(rng, kind, victim, ts):
    """One attack episode -> list of notes. Only pqc_strip is catchable by the rule;
    the other four are what the ML layer is for."""
    base = normal_note(victim, ts)
    if kind == "pqc_strip":
        # MITM strips the PQC groups from ClientHello: only classical left.
        n = dict(base, key_groups_offered=[g for g in victim["groups"] if "MLKEM" not in g],
                 key_group_chosen="x25519", strong_or_weak="weak")
        return [n]
    if kind == "forced_classical":
        # Client still offers PQC but the handshake lands on classical (tampered ServerHello / HRR).
        return [dict(base, key_group_chosen="x25519", strong_or_weak="weak")]
    if kind == "cipher_downgrade":
        # Key groups stay strong, but the cipher drops below what this client normally negotiates.
        weaker = "TLS_AES_128_GCM_SHA256" if victim["cipher"] != "TLS_AES_128_GCM_SHA256" else "AES128-SHA"
        return [dict(base, cipher_suite=weaker)]
    if kind == "burst":
        # A known client suddenly hammers the gateway (credential stuffing / scripted harvest).
        out, t = [], ts
        for _ in range(rng.randint(25, 40)):
            out.append(normal_note(victim, t))
            t += timedelta(seconds=rng.uniform(0.5, 2.0))
        return out
    if kind == "new_scanner":
        # Never-seen client probing with weak, old configurations.
        sid = f"203.0.113.{rng.randint(2, 250)}"
        out, t = [], ts
        for _ in range(rng.randint(8, 15)):
            groups = rng.choice([["secp256r1"], ["ffdhe2048"], ["x25519", "ffdhe2048"], ["secp384r1"]])
            out.append({
                "ts": format_ts(t), "client_id": sid, "tls_version": "TLSv1.2",
                "cipher_suite": rng.choice(["ECDHE-RSA-AES128-SHA", "AES128-SHA"]),
                "key_groups_offered": groups, "key_group_chosen": groups[0], "strong_or_weak": "weak",
            })
            t += timedelta(seconds=rng.uniform(0.3, 3.0))
        return out
    raise ValueError(kind)


def build_files(seed=7):
    rng = random.Random(seed)
    clients = make_clients(rng)
    start = datetime(2026, 10, 10, tzinfo=timezone.utc)
    normal = gen_normal(rng, clients, start, hours=48)

    # Attack stream: the next 6 hours of normal traffic with attack episodes mixed in.
    a_start = start + timedelta(hours=48)
    stream = [(n, None) for n in gen_normal(rng, clients, a_start, hours=6)]
    modern = [c for c in clients if c["kind"] == "modern"]
    for i in range(40):
        kind = ATTACK_TYPES[i % len(ATTACK_TYPES)]
        ts = a_start + timedelta(seconds=rng.uniform(600, 6 * 3600))
        victim = rng.choice(modern)
        stream += [(n, kind) for n in gen_attack(rng, kind, victim, ts)]
    stream.sort(key=lambda x: x[0]["ts"])

    os.makedirs(LOGS, exist_ok=True)
    write_notes(os.path.join(LOGS, "normal_traffic.jsonl"), normal)
    write_notes(os.path.join(LOGS, "attack_traffic.jsonl"), [n for n, _ in stream])
    with open(os.path.join(LOGS, "attack_labels.json"), "w") as f:
        json.dump([k for _, k in stream], f)
    n_att = sum(1 for _, k in stream if k)
    print(f"normal_traffic.jsonl: {len(normal)} notes")
    print(f"attack_traffic.jsonl: {len(stream)} notes ({n_att} attack notes, 40 episodes)")


def live(path, interval=0.4, attack_every=20.0, seed=None):
    """Stand-in for the gateway during the demo: append notes as they happen.

    Timestamps run on a simulated clock at the training traffic's real per-client rate
    (~18x faster than wall time), so the rate features stay meaningful."""
    rng = random.Random(seed)
    clients = make_clients(random.Random(7))
    weights = [c["rate"] for c in clients]
    total_rate = sum(weights) / 3600
    sim = datetime.now(timezone.utc)
    seen, next_attack, i = set(), time.time() + attack_every, 0
    print(f"writing live notes to {path} (Ctrl-C to stop)")
    with open(path, "a") as f:
        while True:
            sim += timedelta(seconds=rng.expovariate(total_rate))
            batch = [normal_note(rng.choices(clients, weights)[0], sim)]
            if time.time() >= next_attack:
                kind = ATTACK_TYPES[i % len(ATTACK_TYPES)]
                pool = [c for c in clients if c["kind"] == "modern" and c["id"] in seen] or \
                       [c for c in clients if c["kind"] == "modern"]
                batch = gen_attack(rng, kind, rng.choice(pool), sim)
                print(f"  -> injecting {kind}")
                i, next_attack = i + 1, time.time() + attack_every
            for n in batch:
                sim = max(sim, datetime.fromisoformat(n["ts"].replace("Z", "+00:00")))
                seen.add(n["client_id"])
                f.write(json.dumps({k: n[k] for k in FIELDS}) + "\n")
                f.flush()
                if len(batch) > 1:
                    time.sleep(0.05)
            time.sleep(interval)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--out", default=os.path.join(LOGS, "connections.jsonl"))
    args = ap.parse_args()
    if args.live:
        live(args.out)
    else:
        build_files()
