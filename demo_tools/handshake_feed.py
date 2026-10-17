"""Simulated handshake notes for the dashboard, until the gateway logs real TLS handshakes.

  python handshake_feed.py normal LOG     -> stream normal traffic into LOG (runs until killed)
  python handshake_feed.py attack LOG     -> append one PQC-strip downgrade for a client already in LOG
  python handshake_feed.py backlog LOG M  -> write M minutes of normal traffic ending now

Uses the detector's own traffic generator, so notes match what the model was trained on.
"""
import json
import os
import sys
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "detector"))
import generate_traffic as gt  # noqa: E402
from schema import FIELDS, is_pqc, parse_ts, read_notes  # noqa: E402


def attack(path):
    notes = read_notes(path)
    seen = {n["client_id"] for n in notes if any(is_pqc(g) for g in n["key_groups_offered"])}
    victims = [c for c in gt.make_clients(__import__("random").Random(7)) if c["id"] in seen]
    if not victims:
        sys.exit("no PQC client in the log yet; let the normal feed run a few seconds first")
    victim = victims[-1]
    ts = parse_ts(notes[-1]["ts"]) + timedelta(seconds=1)
    [note] = gt.gen_attack(__import__("random").Random(), "pqc_strip", victim, ts)
    with open(path, "a") as f:
        f.write(json.dumps({k: note[k] for k in FIELDS}) + "\n")
    print(f"  [attacker] stripped the post-quantum options from {victim['id']}'s handshake: "
          f"now offers only {note['key_groups_offered']}")


def backlog(path, minutes):
    """Write `minutes` of normal traffic ending now, so charts start with history."""
    import random
    from datetime import datetime, timezone
    rng = random.Random(11)
    clients = gt.make_clients(random.Random(7))
    weights = [c["rate"] for c in clients]
    total_rate = sum(weights) / 3600
    end = datetime.now(timezone.utc)
    sim = end - timedelta(minutes=minutes)
    with open(path, "a") as f:
        while True:
            sim += timedelta(seconds=rng.expovariate(total_rate))
            if sim >= end:
                break
            n = gt.normal_note(rng.choices(clients, weights)[0], sim)
            f.write(json.dumps({k: n[k] for k in FIELDS}) + "\n")


if __name__ == "__main__":
    mode, path = sys.argv[1], sys.argv[2]
    if mode == "backlog":
        backlog(path, float(sys.argv[3]))
    elif mode == "normal":
        sys.stdout = open(os.devnull, "w")  # live() prints a banner; keep the demo terminal clean
        gt.live(path, attack_every=float("inf"))
    elif mode == "attack":
        attack(path)
    else:
        sys.exit(__doc__)
