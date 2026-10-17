"""Forced-downgrade attack simulation (demo scene 3).

Story: an attacker on the path forces a client that normally uses hybrid post-quantum
crypto to fall back to classical-only crypto (a real downgrade/stripping attack ends here).
We simulate the *result* of that attack -- the client presenting only classical key
exchange -- and show the gateway and detector react correctly. We do not craft or rewrite
TLS handshake bytes; the client simply offers classical-only, which is the end state a
downgrade attack produces.

    1. alice-laptop connects normally (hybrid X25519MLKEM768)  -> gateway logs "strong"
    2. alice-laptop is forced down to classical-only           -> gateway logs the downgrade
         strict mode: handshake refused, note key_chosen="rejected"
         legacy mode: classical X25519 accepted, note strength="weak"
    3. D's detector sees the same client_id drop its post-quantum offer -> red alert

This drives Person A's testclient; it does not reimplement TLS. Local demo only.

Usage (gateway already running, e.g. ~/gateway/gateway -mode strict):
    python downgrade.py --testclient ~/gateway/testclient/testclient \
        --addr 127.0.0.1:8443 --client-id alice-laptop --notes ~/gateway/logs/connections.jsonl
"""
import argparse
import json
import subprocess
import sys
import time


def connect(testclient, addr, client_id, classical):
    """Run A's testclient once. Returns (ok, output). classical=True offers only classical X25519."""
    cmd = [testclient, "-addr", addr, "-id", client_id]
    if classical:
        cmd.append("-classical")
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return p.returncode == 0, (p.stdout + p.stderr).strip()


def notes_for(path, client_id, since_line):
    """Return gateway notes for this client written after since_line (0-based count)."""
    try:
        with open(path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return [], since_line
    out = []
    for line in lines[since_line:]:
        line = line.strip()
        if not line:
            continue
        try:
            n = json.loads(line)
        except json.JSONDecodeError:
            continue
        if n.get("client_id") == client_id:
            out.append(n)
    return out, len(lines)


def main():
    ap = argparse.ArgumentParser(description="Forced-downgrade attack simulation (scene 3)")
    ap.add_argument("--testclient", default="../../gateway/testclient/testclient",
                    help="path to Person A's testclient binary")
    ap.add_argument("--addr", default="127.0.0.1:8443", help="gateway address")
    ap.add_argument("--client-id", default="alice-laptop", help="client id (SNI), hyphens only")
    ap.add_argument("--notes", default="", help="gateway connection-note file to read back (optional)")
    args = ap.parse_args()

    mark = 0
    if args.notes:
        try:
            mark = sum(1 for _ in open(args.notes))
        except FileNotFoundError:
            mark = 0

    print(f"[1] {args.client_id} connects normally (hybrid post-quantum)...")
    ok, out = connect(args.testclient, args.addr, args.client_id, classical=False)
    print("    " + out.replace("\n", "\n    "))
    if not ok:
        print("    ! baseline hybrid connection failed; is the gateway running?", file=sys.stderr)
        return 2

    time.sleep(0.5)
    print(f"\n[2] attacker forces {args.client_id} down to classical-only...")
    ok, out = connect(args.testclient, args.addr, args.client_id, classical=True)
    print("    " + out.replace("\n", "\n    "))
    if ok:
        print("    -> gateway ACCEPTED classical (legacy mode): logged as a weak connection.")
    else:
        print("    -> gateway REFUSED classical (strict mode): this is the intended defence.")

    if args.notes:
        time.sleep(0.5)
        notes, _ = notes_for(args.notes, args.client_id, mark)
        print(f"\n[3] gateway notes for {args.client_id} this run:")
        for n in notes:
            print(f"    chosen={n.get('key_chosen'):<14} strength={n.get('strength'):<6} "
                  f"offered={n.get('keys_offered')}")
        strong = any(n.get("strength") == "strong" for n in notes)
        downgraded = any(n.get("strength") == "weak" for n in notes)
        if strong and downgraded:
            print("    -> DOWNGRADE PATTERN PRESENT: same client went strong then weak. "
                  "D's detector should raise a red alert.")
        else:
            print("    -> expected one strong note and one weak/rejected note for this client.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
