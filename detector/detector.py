"""Two-layer downgrade / anomaly tripwire over connection notes (INTERFACES.md §1).

Layer 1 (rule):  a client that offered a post-quantum key group before now offers only
                 classical groups -> downgrade alert. Deterministic, zero false positives.
Layer 2 (model): a k-nearest-neighbour novelty detector trained on normal traffic, over
                 per-connection and per-client behavioural features. A connection far from
                 every normal connection it has seen is flagged. Catches what the rule can't see: PQC offered
                 but not chosen, cipher-only downgrades, connection bursts, new clients probing
                 with weak configurations.

  det = Detector(); det.train(normal_notes); det.check(note) -> {alert, by, reason, score}

  python detector.py   -> self-test on logs/attack_traffic.jsonl (needs generate_traffic.py first)
"""
import json
import math
import os
from collections import Counter, deque

import numpy as np
from sklearn.neighbors import NearestNeighbors

from schema import is_pqc, cipher_strength, parse_ts, read_notes

HERE = os.path.dirname(os.path.abspath(__file__))
LOGS = os.path.join(HERE, "..", "logs")

FEATURES = [
    "tls13", "offers_pqc", "chosen_pqc", "pqc_offered_not_chosen", "cipher_strength",
    "strength_drop", "n_groups", "new_group_set", "conn_per_min", "conn_per_10min",
    "hour_sin", "hour_cos",
]

# How each feature reads in an alert when it is outside its normal range.
EXPLAIN = {
    "tls13": "TLS version differs from normal traffic",
    "offers_pqc": "no post-quantum key group offered",
    "chosen_pqc": "classical key exchange negotiated",
    "pqc_offered_not_chosen": "client offered PQC but handshake settled on classical",
    "cipher_strength": "weak cipher suite",
    "strength_drop": "cipher weaker than this client normally negotiates",
    "n_groups": "unusual number of key groups offered",
    "new_group_set": "key-group set never seen from this client",
    "conn_per_min": "connection burst (per minute)",
    "conn_per_10min": "unusually high connection rate (per 10 min)",
    "hour": "unusual time of day",
}


class _Client:
    def __init__(self):
        self.times = deque()          # recent connection times (epoch s), last 10 min
        self.n = 0
        self.pqc_seen = 0             # handshakes where a PQC group was offered
        self.strengths = Counter()
        self.group_sets = set()
        self.downgrades = 0


class Detector:
    def __init__(self, threshold_quantile=0.001, k=5):
        self.q = threshold_quantile   # fraction of normal training traffic allowed above threshold
        self.k = k
        self.model = None
        self.threshold = None
        self.reset()

    def reset(self):
        self.clients = {}

    # ---------- features ----------
    def features(self, note, c):
        t = parse_ts(note["ts"])
        now = t.timestamp()
        offered = list(note["key_groups_offered"])
        offers_pqc = any(is_pqc(g) for g in offered)
        chosen_pqc = is_pqc(note["key_group_chosen"])
        strength = cipher_strength(note["cipher_suite"])
        usual = c.strengths.most_common(1)[0][0] if c.strengths else strength
        while c.times and now - c.times[0] > 600:
            c.times.popleft()
        per_min = 1 + sum(1 for x in c.times if now - x <= 60)
        per_10 = 1 + len(c.times)
        hour = t.hour + t.minute / 60
        return [
            float(note["tls_version"] in ("TLSv1.3", "1.3", "TLS1.3")),
            float(offers_pqc),
            float(chosen_pqc),
            float(offers_pqc and not chosen_pqc),
            float(strength),
            float(max(0, usual - strength)),
            float(len(offered)),
            float(c.n >= 3 and frozenset(offered) not in c.group_sets),
            math.log1p(per_min),
            math.log1p(per_10),
            math.sin(hour / 24 * 2 * math.pi),
            math.cos(hour / 24 * 2 * math.pi),
        ]

    def _rule(self, note, c):
        offered = note["key_groups_offered"]
        if c.pqc_seen and not any(is_pqc(g) for g in offered):
            return (f"DOWNGRADE: {note['client_id']} offered post-quantum groups in "
                    f"{c.pqc_seen} earlier handshake(s), now offers only classical {offered}")
        return None

    def _update(self, note, c, downgrade):
        c.times.append(parse_ts(note["ts"]).timestamp())
        c.n += 1
        if any(is_pqc(g) for g in note["key_groups_offered"]):
            c.pqc_seen += 1
        c.strengths[cipher_strength(note["cipher_suite"])] += 1
        c.group_sets.add(frozenset(note["key_groups_offered"]))
        c.downgrades += int(downgrade)

    def _client(self, cid):
        return self.clients.setdefault(cid, _Client())

    # ---------- train / check ----------
    def train(self, normal_notes):
        """Fit on normal traffic. Client history built here is kept, so a stream that
        continues the same traffic is checked against what each client normally does."""
        self.reset()
        X = []
        for n in sorted(normal_notes, key=lambda n: parse_ts(n["ts"])):
            c = self._client(n["client_id"])
            X.append(self.features(n, c))
            self._update(n, c, False)
        self.X = np.array(X)
        self.lo, self.hi = self.X.min(axis=0), self.X.max(axis=0)
        self.mu = self.X.mean(axis=0)
        self.median = np.median(self.X, axis=0)
        self.sd = np.maximum(self.X.std(axis=0), 0.1)  # floor: constant features still count
        self.model = NearestNeighbors(n_neighbors=self.k + 1).fit(self._scale(self.X))
        d, _ = self.model.kneighbors()                  # training points, excluding themselves
        self.threshold = float(np.quantile(d[:, :self.k].mean(axis=1), 1 - self.q))
        return self

    def _scale(self, X):
        return (np.asarray(X) - self.mu) / self.sd

    def _score(self, x):
        """Mean distance to the k nearest normal connections (higher = more anomalous)."""
        d, _ = self.model.kneighbors(self._scale([x]), n_neighbors=self.k)
        return float(d[0].mean())

    def check(self, note):
        c = self._client(note["client_id"])
        x = self.features(note, c)
        score = self._score(x) if self.model else 0.0
        rule = self._rule(note, c)
        if rule:
            out = {"alert": True, "by": "rule", "reason": rule, "factors": ["pqc_stripped"]}
        elif self.model and score > self.threshold:
            factors = self._why(x, score)
            why = "; ".join(EXPLAIN[f] for f in factors) or "unusual combination of handshake features"
            if c.downgrades:  # context only: as a feature it would keep the client red forever
                why += f"; client already had {c.downgrades} downgrade alert(s)"
            out = {"alert": True, "by": "model", "reason": "ANOMALY: " + why, "factors": factors}
        else:
            out = {"alert": False, "by": None, "reason": "normal", "factors": []}
        out["prior_downgrades"] = c.downgrades
        out["score"] = round(score, 4)
        self._update(note, c, bool(rule))
        return out

    def _why(self, x, score):
        """Features outside anything seen in normal traffic, then the features whose
        replacement by a typical value lowers the anomaly score the most. Returns feature names."""
        out = [f for f, v, lo, hi in zip(FEATURES, x, self.lo, self.hi)
               if v < lo - 1e-9 or v > hi + 1e-9]
        trial = np.tile(np.asarray(x, dtype=float), (len(x), 1))
        np.fill_diagonal(trial, self.median)
        drops = score - self.model.kneighbors(self._scale(trial), n_neighbors=self.k)[0].mean(axis=1)
        for i in np.argsort(-drops):
            if drops[i] < 0.2 * score:
                break
            out.append(FEATURES[i])
        out = [f.replace("hour_sin", "hour").replace("hour_cos", "hour") for f in out]
        return list(dict.fromkeys(out))[:3]


def self_test():
    normal = read_notes(os.path.join(LOGS, "normal_traffic.jsonl"))
    stream = read_notes(os.path.join(LOGS, "attack_traffic.jsonl"))
    with open(os.path.join(LOGS, "attack_labels.json")) as f:
        labels = json.load(f)

    det = Detector().train(normal)
    results = [det.check(n) for n in stream]

    by_type = {}
    fp = negatives = 0
    for r, lab in zip(results, labels):
        if lab is None:
            negatives += 1
            fp += r["alert"]
            continue
        d = by_type.setdefault(lab, Counter())
        d["total"] += 1
        d[r["by"] or "missed"] += 1

    print(f"trained on {len(normal)} normal notes; threshold={det.threshold:.3f} (kNN distance)\n")
    print(f"{'attack type':<18}{'notes':>6}{'rule':>6}{'model':>7}{'missed':>8}")
    for k, d in sorted(by_type.items()):
        print(f"{k:<18}{d['total']:>6}{d['rule']:>6}{d['model']:>7}{d['missed']:>8}")
    tot = sum(by_type.values(), Counter())
    print(f"{'ALL':<18}{tot['total']:>6}{tot['rule']:>6}{tot['model']:>7}{tot['missed']:>8}")
    print(f"\nfalse positives on normal notes: {fp}/{negatives} ({100 * fp / max(negatives, 1):.2f}%)")

    print("\nsample alerts:")
    shown = set()
    for n, r, lab in zip(stream, results, labels):
        if r["alert"] and (lab, r["by"]) not in shown:
            shown.add((lab, r["by"]))
            print(f"  [{r['by']:<5}] ({lab}) {n['client_id']}: {r['reason']}")


if __name__ == "__main__":
    self_test()
