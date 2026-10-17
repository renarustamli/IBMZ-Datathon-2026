import csv
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(7)  # fixed seed: same files every time

OUT = Path(__file__).parent
# fixed date so output is repeatable
START = datetime(2026, 10, 5, tzinfo=timezone.utc)
DAYS = 7
N_NORMAL = 600
N_BURSTS = 10

PQ = "x25519-mlkem768"
# modern clients: always offer the quantum-safe group
MODERN = [f"client-m{i}" for i in range(1, 9)]
# legit clients that only know classical locks
CLASSICAL = [f"client-c{i}" for i in range(1, 5)]
# legit old systems that only use the weak lock
LEGACY = [f"client-l{i}" for i in range(1, 4)]

TLS13 = "TLS1.3"
AES_SUITE = "TLS_AES_256_GCM_SHA384"
TOY_SUITE = "TOY-RSA64+AES256GCM"


def note(ts, client_id, offered, chosen, tls, cipher, status="ok"):
    # EDIT this to match the connection note format you agreed with A and D
    return {
        "time": ts.isoformat(),
        "client_id": client_id,
        "tls_version": tls,
        "cipher_suite": cipher,
        "key_groups_offered": offered,
        "key_group_chosen": chosen,
        "strong_or_weak": "strong" if "mlkem" in chosen else "weak",
        "status": status,
    }


def random_time(day_weight=0.7):
    """day_weight = chance the row lands in working hours (8am to 6pm)."""
    day = random.randrange(DAYS)
    if random.random() < day_weight:
        hour = random.randint(8, 17)
    else:
        hour = random.choice(list(range(0, 8)) + list(range(18, 24)))
    return START + timedelta(days=day, hours=hour,
                             minutes=random.randint(0, 59), seconds=random.randint(0, 59))


def normal_row():
    ts = random_time(0.7)
    who = random.choices(["modern", "classical", "legacy"],
                         weights=[60, 25, 15])[0]

    if who == "modern":
        roll = random.random()
        if roll < 0.02:
            # harmless oddity: a modern client occasionally shows up with classical only
            return note(ts, random.choice(MODERN), ["x25519", "secp256r1"], "x25519",
                        TLS13, AES_SUITE), "benign_oddity"
        if roll < 0.04:
            # noise: the connection just failed
            return note(ts, random.choice(MODERN), [PQ, "x25519", "secp256r1"], PQ,
                        TLS13, AES_SUITE, status=random.choice(["timeout", "reset"])), "noise"
        return note(ts, random.choice(MODERN), [PQ, "x25519", "secp256r1"], PQ,
                    TLS13, AES_SUITE), "modern_client"

    if who == "classical":
        return note(ts, random.choice(CLASSICAL), ["x25519", "secp256r1"], "x25519",
                    TLS13, AES_SUITE), "classical_client"

    return note(ts, random.choice(LEGACY), ["toy-rsa-64"], "toy-rsa-64",
                "toy-legacy", TOY_SUITE), "legacy_client"


def attack_burst():
    """A burst of downgrade attempts against one modern client, mostly at odd hours."""
    victim = random.choice(MODERN)
    t = random_time(0.4)
    style = random.choice(["toy", "classical"])
    rows = []
    for _ in range(random.randint(3, 7)):
        t += timedelta(seconds=random.randint(5, 90))
        if style == "toy":
            n = note(t, victim, ["toy-rsa-64"],
                     "toy-rsa-64", "toy-legacy", TOY_SUITE)
        else:
            n = note(t, victim, ["x25519", "secp256r1"],
                     "x25519", TLS13, AES_SUITE)
        rows.append((n, "attack"))
    return rows


def write_jsonl(path, rows):
    with open(path, "w") as f:
        for i, (n, _) in enumerate(rows, start=1):
            f.write(json.dumps({"row_id": i, **n}) + "\n")


def sort_by_time(rows):
    return sorted(rows, key=lambda r: r[0]["time"])


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def main():
    normal = sort_by_time([normal_row() for _ in range(N_NORMAL)])
    attacks = [r for _ in range(N_BURSTS) for r in attack_burst()]
    combined = sort_by_time(normal + attacks)

    write_jsonl(OUT / "normal.jsonl", normal)
    write_jsonl(OUT / "with_attacks.jsonl", combined)

    with open(OUT / "answer_key.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["row_id", "is_attack", "kind"])
        for i, (_, kind) in enumerate(combined, start=1):
            w.writerow([i, int(kind == "attack"), kind])

    pct = 100 * len(attacks) / len(combined)
    print(f"normal.jsonl: {len(normal)} rows")
    print(
        f"with_attacks.jsonl: {len(combined)} rows, {len(attacks)} attacks ({pct:.1f}%)")
    for name in ["normal.jsonl", "with_attacks.jsonl", "answer_key.csv"]:
        print(f"  {name} hash: {sha(OUT / name)}")


if __name__ == "__main__":
    main()
