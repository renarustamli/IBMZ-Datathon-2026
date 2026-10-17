"""Connection-note schema (INTERFACES.md §1) and the crypto vocabulary shared by
the generator and the detector.

One JSON object per line in logs/connections.jsonl:
  ts, client_id, tls_version, cipher_suite, key_groups_offered, key_group_chosen, strong_or_weak

Value formats below are our best guess until INTERFACES.md is confirmed —
if the gateway writes different strings, change them here only.
"""
import json
from datetime import datetime, timezone

FIELDS = ["ts", "client_id", "tls_version", "cipher_suite",
          "key_groups_offered", "key_group_chosen", "strong_or_weak"]

# Hybrid / pure post-quantum key-exchange groups (IANA TLS names, as Go/OpenSSL print them).
PQC_GROUPS = {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM768", "MLKEM1024"}
CLASSICAL_GROUPS = {"x25519", "secp256r1", "secp384r1", "secp521r1", "ffdhe2048"}

# 2 = strong, 1 = acceptable, 0 = weak (CBC / SHA-1 / no AEAD).
CIPHER_STRENGTH = {
    "TLS_AES_256_GCM_SHA384": 2,
    "TLS_CHACHA20_POLY1305_SHA256": 2,
    "TLS_AES_128_GCM_SHA256": 1,
    "ECDHE-RSA-AES256-GCM-SHA384": 2,
    "ECDHE-RSA-AES128-GCM-SHA256": 1,
    "ECDHE-RSA-AES128-SHA": 0,
    "AES128-SHA": 0,
}


def is_pqc(group):
    return group in PQC_GROUPS or "MLKEM" in str(group).upper()


def cipher_strength(suite):
    if suite in CIPHER_STRENGTH:
        return CIPHER_STRENGTH[suite]
    s = str(suite).upper()
    if "256_GCM" in s or "256-GCM" in s or "CHACHA20" in s:
        return 2
    if "GCM" in s:
        return 1
    return 0


def parse_ts(ts):
    """ISO-8601 string (with or without 'Z') or epoch seconds -> aware datetime."""
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def format_ts(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# Field names the gateway skeleton (a-gateway, gateway/main.go) writes instead of §1's.
ALIASES = {"time": "ts", "cipher": "cipher_suite", "keys_offered": "key_groups_offered",
           "key_chosen": "key_group_chosen", "strength": "strong_or_weak"}


def normalize(note):
    """Map any accepted spelling of a note onto the §1 field names."""
    n = dict(note)
    for alt, field in ALIASES.items():
        if field not in n and alt in n:
            n[field] = n.pop(alt)
    # Gateway placeholder client_id: fall back to the remote IP (port stripped, IPv6-safe).
    if n.get("client_id") in (None, "", "unknown") and n.get("client"):
        n["client_id"] = str(n["client"]).rsplit(":", 1)[0].strip("[]")
    n["key_groups_offered"] = list(n.get("key_groups_offered") or [])
    return n


def read_notes(path):
    with open(path) as f:
        return [normalize(json.loads(line)) for line in f if line.strip()]


def write_notes(path, notes):
    with open(path, "w") as f:
        for n in notes:
            f.write(json.dumps({k: n[k] for k in FIELDS}) + "\n")
