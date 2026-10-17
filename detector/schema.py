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
    g = str(group).upper()
    return group in PQC_GROUPS or "MLKEM" in g or "KYBER" in g


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
    n["key_groups_offered"] = [group_name(g) for g in (n.get("key_groups_offered") or [])]
    if "key_group_chosen" in n:
        n["key_group_chosen"] = group_name(n["key_group_chosen"])
    # Go writes "TLS 1.3"; normal traffic uses "TLSv1.3".
    v = str(n.get("tls_version", ""))
    if v.startswith("TLS 1."):
        n["tls_version"] = "TLSv" + v[4:]
    return n


# IANA TLS supported-group codepoints. Go prints groups it has no name for as
# "CurveID(4588)"; the gateway writes them as "other-4588".
GROUP_CODES = {
    23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519", 256: "ffdhe2048",
    4587: "SecP256r1MLKEM768", 4588: "X25519MLKEM768", 4589: "SecP384r1MLKEM1024",
    25497: "X25519Kyber768Draft00",
}


# Go's crypto/tls names for classical groups.
GO_NAMES = {"X25519": "x25519", "CurveP256": "secp256r1", "CurveP384": "secp384r1", "CurveP521": "secp521r1",
            "P-256": "secp256r1", "P-384": "secp384r1", "P-521": "secp521r1"}


def group_name(g):
    s = str(g).strip()
    code = s.removeprefix("other-").removeprefix("CurveID(").removesuffix(")")
    if code.isdigit():
        return GROUP_CODES.get(int(code), s)
    return GO_NAMES.get(s, s)


def read_notes(path):
    with open(path) as f:
        return [normalize(json.loads(line)) for line in f if line.strip()]


def write_notes(path, notes):
    with open(path, "w") as f:
        for n in notes:
            f.write(json.dumps({k: n[k] for k in FIELDS}) + "\n")
