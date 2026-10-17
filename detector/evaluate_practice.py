"""Score the detector against C's labelled practice data (practice_data/).

Trains on normal.jsonl, checks with_attacks.jsonl, compares with answer_key.csv.

  python evaluate_practice.py
"""
import csv
import os
from collections import Counter

from detector import Detector, HERE, REPEAT_WINDOW
from schema import read_notes, parse_ts

DATA = os.path.join(HERE, "..", "practice_data")


def main():
    det = Detector().train(read_notes(os.path.join(DATA, "normal.jsonl")))
    det.reset()  # with_attacks.jsonl repeats the normal rows; judge it from a clean history
    with open(os.path.join(DATA, "answer_key.csv")) as f:
        kind = {r["row_id"]: r["kind"] for r in csv.DictReader(f)}

    outcome = Counter()
    bursts = {}  # (client, burst start) -> caught?
    for n in read_notes(os.path.join(DATA, "with_attacks.jsonl")):
        r = det.check(n)
        k = kind[str(n["row_id"])]
        outcome[k, "ALERT" if r["alert"] else r["by"] or "ok"] += 1
        if k == "attack":
            t = parse_ts(n["ts"]).timestamp()
            key = next((b for b in bursts if b[0] == n["client_id"] and 0 <= t - b[2] <= REPEAT_WINDOW), None)
            if key is None:
                key = (n["client_id"], len(bursts), t)
                bursts[key] = False
            else:  # slide the window so a long burst stays one episode
                bursts[(key[0], key[1], t)] = bursts.pop(key)
                key = (key[0], key[1], t)
            bursts[key] |= r["alert"]

    print(f"{'row kind':<18}{'ALERT':>7}{'watch':>7}{'ok':>6}")
    for k in sorted({k for k, _ in outcome}):
        print(f"{k:<18}{outcome[k, 'ALERT']:>7}{outcome[k, 'watch']:>7}{outcome[k, 'ok']:>6}")
    normal_alerts = sum(v for (k, o), v in outcome.items() if k != "attack" and o == "ALERT")
    normal_rows = sum(v for (k, _), v in outcome.items() if k != "attack")
    print(f"\nattack bursts caught: {sum(bursts.values())}/{len(bursts)}")
    print(f"false alarms on normal rows: {normal_alerts}/{normal_rows}")


if __name__ == "__main__":
    main()
