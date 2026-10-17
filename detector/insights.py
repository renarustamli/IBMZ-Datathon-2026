"""Running aggregates behind the dashboard: what the raw feed can't show at a glance.

  ins = Insights(); ins.add(note, result); ins.snapshot() -> dict for /api/state

- timeline:    connections per minute, quantum-safe vs classical, with alert counts
- clients:     per-client posture, risk-sorted -> which clients need upgrading or investigating
- groups:      which key exchanges are actually negotiated
- alert_types: what kinds of attack the detector is seeing
- scores:      recent anomaly scores against the model threshold (is the AI working?)
"""
from collections import Counter, OrderedDict, deque

from schema import is_pqc, parse_ts

MAX_MINUTES = 60
MAX_SCORES = 150

# Short labels for the detector's factor names (detector.FEATURES + the rule's "pqc_stripped").
FACTOR_LABELS = {
    "pqc_stripped": "PQC stripped (downgrade)",
    "pqc_offered_not_chosen": "PQC offered, classical chosen",
    "chosen_pqc": "classical key exchange",
    "offers_pqc": "no PQC offered",
    "strength_drop": "weaker cipher than usual",
    "cipher_strength": "weak cipher",
    "tls13": "old TLS version",
    "conn_per_min": "connection burst",
    "conn_per_10min": "high connection rate",
    "new_group_set": "new key-group set",
    "n_groups": "unusual key-group list",
    "hour": "unusual time of day",
}

# Worst first. Each status ships with an icon + label in the UI, never colour alone.
STATUS_ORDER = {"downgraded": 0, "anomalous": 1, "needs_upgrade": 2, "quantum_safe": 3}


class Insights:
    def __init__(self):
        self.reset()

    def reset(self):
        self.minutes = OrderedDict()   # "YYYY-MM-DDTHH:MM" -> Counter(strong, weak, refused, rule, model)
        self.clients = {}
        self.groups = Counter()
        self.alert_types = Counter()
        self.scores = deque(maxlen=MAX_SCORES)
        self.totals = Counter()

    def add(self, note, r):
        if "client_id" not in note:   # unparsed line
            return
        cid = note["client_id"]
        chosen = note.get("key_group_chosen", "")
        refused = chosen == "rejected"           # strict-mode gateway refused the handshake
        strong = note.get("strong_or_weak") == "strong"
        kind = "strong" if strong else "refused" if refused else "weak"
        offered_pq = any(is_pqc(g) for g in note.get("key_groups_offered") or [])

        self.totals[kind] += 1
        self.totals["total"] += 1
        try:
            minute = parse_ts(note["ts"]).strftime("%Y-%m-%dT%H:%M")
        except Exception:
            minute = None
        if minute:
            b = self.minutes.get(minute)
            if b is None:
                b = self.minutes[minute] = Counter()
                while len(self.minutes) > MAX_MINUTES:
                    self.minutes.popitem(last=False)
            b[kind] += 1
            if r.get("by"):
                b[r["by"]] += 1
        if not refused and chosen:
            self.groups[chosen] += 1

        c = self.clients.setdefault(cid, {"id": cid, "n": 0, "strong": 0, "refused": 0, "rule": 0, "model": 0,
                                          "offered_pq": 0, "last_reason": ""})
        c["n"] += 1
        c["strong"] += strong
        c["refused"] += refused
        c["offered_pq"] += offered_pq
        c.update(last_ts=note.get("ts"), tls=note.get("tls_version"), cipher=note.get("cipher_suite"), group=chosen)
        if r.get("by"):
            c[r["by"]] += 1
            c["last_reason"] = r.get("plain") or r.get("reason", "")
            factors = r.get("factors") or []
            self.alert_types[FACTOR_LABELS.get(factors[0], factors[0]) if factors else "other anomaly"] += 1

        self.scores.append({"ts": note.get("ts"), "client": cid, "score": r.get("score", 0), "by": r.get("by")})

    @staticmethod
    def _status(c):
        if c["rule"]:
            return "downgraded"
        if c["model"]:
            return "anomalous"
        if not c["offered_pq"]:
            return "needs_upgrade"
        return "quantum_safe"

    def snapshot(self):
        clients = []
        for c in self.clients.values():
            done = c["n"] - c["refused"]
            clients.append({**c, "status": self._status(c),
                            "pq_share": round(c["strong"] / done, 3) if done else 0.0})
        clients.sort(key=lambda c: (STATUS_ORDER[c["status"]], -(c["rule"] + c["model"]), -c["n"]))
        posture = Counter(c["status"] for c in clients)
        mins = list(self.minutes.items())
        recent = mins[-5:]
        return {
            "totals": dict(self.totals),
            "rate_per_min": round(sum(sum(b[k] for k in ("strong", "weak", "refused")) for _, b in recent)
                                  / len(recent), 1) if recent else 0,
            "timeline": [{"t": t, **{k: b[k] for k in ("strong", "weak", "refused", "rule", "model")}}
                         for t, b in mins],
            "clients": clients,
            "posture": {k: posture.get(k, 0) for k in STATUS_ORDER},
            "groups": self.groups.most_common(8),
            "alert_types": self.alert_types.most_common(8),
            "scores": list(self.scores),
        }
