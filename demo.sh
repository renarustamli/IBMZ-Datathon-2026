#!/usr/bin/env bash
# One-command demo of the Quantum-Safe Gateway.
#
#   ./demo.sh           walk through the story, pausing for Enter between steps
#   ./demo.sh --auto    no pauses (rehearsal / CI)
#
# The animated pitch is separate: animations/pitch.html (built by animations/render.sh).
#
# Steps:
#   1. Harvest now, decrypt later: the attacker records traffic to the legacy server and cracks it
#   2. The same attack through the gateway
#   3. Data at rest: records locked with ML-KEM + AES-256-GCM
#   4. Downgrade attack: the AI tripwire dashboard turns red
#   5. Tamper-evident logs: editing the audit log is caught (ML-DSA seals)
#
# Everything it creates goes in run/ (git-ignored). Override ports/paths with env vars below.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
RUN="$ROOT/run"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
LEGACY_PORT=9000                    # hard-coded in legacy_server/server.py
TAP_DIRECT_PORT="${TAP_DIRECT_PORT:-9001}"
GATEWAY_PORT="${GATEWAY_PORT:-8443}"
TAP_GATEWAY_PORT="${TAP_GATEWAY_PORT:-8442}"
DASH_PORT="${DASH_PORT:-5050}"      # not 5000: macOS AirPlay Receiver sits there
GATEWAY_ARGS="${GATEWAY_ARGS:-}"    # extra flags for gateway/gateway
AUTO=0
for a in "$@"; do
  case "$a" in --auto) AUTO=1 ;; *) echo "usage: ./demo.sh [--auto]"; exit 1 ;; esac
done

if [[ -t 1 ]]; then B=$'\e[1m'; G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; D=$'\e[2m'; N=$'\e[0m'; else B= G= R= Y= D= N=; fi
say()   { printf '%s\n' "$*"; }
title() { printf '\n%s━━━ %s ━━━%s\n' "$B" "$*" "$N"; }
note()  { printf '%s%s%s\n' "$D" "$*" "$N"; }
warn()  { printf '%s%s%s\n' "$Y" "$*" "$N"; }
short() { sed "s#$ROOT/##g"; }   # show repo-relative paths to the audience
pause() { if (( AUTO )); then sleep 1; else read -r -p "${D}[Enter to continue]${N} " _; fi; }

PIDS=()
bg() { local log="$RUN/$1.log"; shift; "$@" >"$log" 2>&1 & PIDS+=($!); }
cleanup() { for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

wait_port() {  # wait until something listens on $1
  for _ in $(seq 50); do "$PY" -c "import socket,sys; socket.create_connection(('127.0.0.1',$1),0.2)" 2>/dev/null && return 0; sleep 0.2; done
  say "${R}nothing came up on port $1 — see $RUN/*.log${N}"; exit 1
}
wait_log() {   # wait until $RUN/$1.log contains $2 (a port check would leave a fake connection in the logs)
  for _ in $(seq 50); do grep -q "$2" "$RUN/$1.log" 2>/dev/null && return 0; sleep 0.2; done
  say "${R}$1 did not start — see $RUN/$1.log${N}"; exit 1
}
port_free() { ! "$PY" -c "import socket; socket.create_connection(('127.0.0.1',$1),0.2)" 2>/dev/null; }

# ───────────────────────────── setup ─────────────────────────────
title "Setup"
[[ -x "$PY" ]] || { say "${R}No Python venv. Run:${N} python3 -m venv .venv && .venv/bin/pip install -r detector/requirements.txt -r pqc/requirements-crypto.txt sympy"; exit 1; }
"$PY" -c "import flask, sklearn, sympy, cryptography, kyber_py, dilithium_py" 2>/dev/null \
  || { say "${R}Missing packages. Run:${N} .venv/bin/pip install -r detector/requirements.txt -r pqc/requirements-crypto.txt sympy"; exit 1; }
for p in $LEGACY_PORT $TAP_DIRECT_PORT $GATEWAY_PORT $TAP_GATEWAY_PORT $DASH_PORT; do
  port_free "$p" || { say "${R}Port $p is already in use (an old demo still running?)${N}"; exit 1; }
done

rm -rf "$RUN"; mkdir -p "$RUN"
export QSAFE_KEYS="$RUN/keys"
"$PY" "$ROOT/pqc/qsafe_crypto.py" keygen >/dev/null && note "post-quantum keys (ML-KEM-768, ML-DSA-65) -> run/keys/"
[[ -f "$ROOT/logs/normal_traffic.jsonl" ]] || (cd "$ROOT/detector" && "$PY" generate_traffic.py >/dev/null)
note "detector training traffic ready"

HAVE_GATEWAY=0
if command -v go >/dev/null; then
  (cd "$ROOT/gateway" && go build -o gateway . && go build -o testclient/testclient ./testclient) && HAVE_GATEWAY=1 && note "gateway + test client built"
  # demo certificate, as in gateway/README.md (self-signed, never committed)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj "/CN=localhost" \
    -keyout "$RUN/key.pem" -out "$RUN/cert.pem" 2>/dev/null
else
  warn "Go is not installed: step 2 will be skipped (brew install go)"
fi

cd "$ROOT/legacy_server"; bg legacy "$PY" server.py; cd "$ROOT"   # not a subshell: cleanup needs the PID
wait_port $LEGACY_PORT
bg tap_direct "$PY" -u "$ROOT/demo_tools/wiretap.py" $TAP_DIRECT_PORT 127.0.0.1:$LEGACY_PORT "$RUN/captures_direct"
wait_log tap_direct listening
note "legacy bank server on :$LEGACY_PORT (toy 64-bit RSA, unchanged)"

# ──────────────────── 1. harvest now, decrypt later ────────────────────
title "1. Harvest now, decrypt later — the legacy server"
say "Bank clients fetch customer records from the old server. An eavesdropper"
say "on the network quietly records every session."
note "(Scaled-down illustration: a deliberately tiny 64-bit RSA key stands in for what a"
note " future quantum computer could do to real RSA. This is not a break of production RSA.)"
pause
"$PY" -u "$ROOT/demo_tools/demo_client.py" 127.0.0.1:$TAP_DIRECT_PORT --count 5 --client-prefix legacy-branch
sleep 0.5; tail -n 5 "$RUN/tap_direct.log"
say ""
say "${B}Years later, the attacker runs the recordings through a code-breaker:${N}"
pause
say "${R}$("$PY" "$ROOT/attacker/attack.py" "$RUN/captures_direct" | short)${N}"

# ──────────────────── 2. same attack, through the gateway ────────────────────
title "2. The same attack, through the quantum-safe gateway"
if (( HAVE_GATEWAY )); then
  # shellcheck disable=SC2086
  bg gateway "$ROOT/gateway/gateway" -mode strict -listen 127.0.0.1:$GATEWAY_PORT -backend 127.0.0.1:$LEGACY_PORT \
     -cert "$RUN/cert.pem" -key "$RUN/key.pem" -notes "$RUN/gateway_notes.jsonl" $GATEWAY_ARGS
  wait_log gateway "mode) on"
  bg tap_gateway "$PY" -u "$ROOT/demo_tools/wiretap.py" $TAP_GATEWAY_PORT 127.0.0.1:$GATEWAY_PORT "$RUN/captures_gateway"
  wait_log tap_gateway listening
  say "Now the clients connect through the gateway (hybrid X25519 + ML-KEM-768 TLS)."
  say "The legacy server is untouched; the eavesdropper records the client <-> gateway"
  say "link the same way as before."
  pause
  "$PY" -u "$ROOT/demo_tools/demo_client.py" 127.0.0.1:$TAP_GATEWAY_PORT --tls --count 5 --client-prefix pq-branch
  sleep 0.5; tail -n 5 "$RUN/tap_gateway.log"
  say ""
  say "${B}The attacker runs the same code-breaker on these recordings:${N}"
  pause
  OUT="$("$PY" "$ROOT/attacker/attack.py" "$RUN/captures_gateway" | short)"
  if grep -q "Recovered secret data from 0 of" <<<"$OUT"; then say "${G}$OUT${N}"; say "${G}${B}Nothing recovered: the captured bytes stay unreadable.${N}"
  else say "${R}$OUT${N}"; warn "Data leaked through the gateway — check run/gateway.log."; fi
  say "What the gateway logged for these connections:"
  tail -n 5 "$RUN/gateway_notes.jsonl" | "$PY" -c "import json,sys
for l in sys.stdin: n=json.loads(l); print(f\"  {n['client_id']:<12} {n['tls_version']}  key exchange {n['key_chosen']:<15} {n['strength']}\")"
  say ""
  say "${B}An attacker tries to force a client back onto the old, classical lock:${N}"
  pause
  if OUT="$("$ROOT/gateway/testclient/testclient" -addr 127.0.0.1:$GATEWAY_PORT -id pq-branch-2 -classical 2>&1)"; then
    say "${R}$OUT${N}"; warn "The gateway accepted a classical-only handshake — is it in strict mode?"
  else
    say "  [client] handshake failed: ${OUT#*handshake failed: }"
    tail -n 1 "$RUN/gateway_notes.jsonl" | "$PY" -c "import json,sys; n=json.loads(sys.stdin.read())
print(f\"  gateway log: {n['client_id']} offered only {n['keys_offered']} -> {n['key_chosen']}\")"
    say "${G}${B}Refused: in strict mode the gateway only speaks the quantum-safe lock.${N}"
  fi
else
  warn "Skipped: Go is not installed, so the gateway cannot be built."
fi

# ──────────────────── 3. data at rest ────────────────────
title "3. Data at rest — locked with ML-KEM-768 + AES-256-GCM"
cp "$ROOT/legacy_server/records.json" "$RUN/bank_records.json"
say "The bank's records file on disk:"
head -c 300 "$RUN/bank_records.json"; say "…"
pause
"$PY" "$ROOT/pqc/qsafe_crypto.py" lock "$RUN/bank_records.json" | short
say "What a thief who copies the disk sees:"
"$PY" -c "import sys; b=open(sys.argv[1],'rb').read(); print(b[:150].hex(), '…', f'({len(b)} bytes)')" "$RUN/bank_records.json.locked"
"$PY" "$ROOT/pqc/qsafe_crypto.py" unlock "$RUN/bank_records.json.locked" | short
if cmp -s "$RUN/bank_records.json" "$RUN/bank_records.json.unlocked"; then say "${G}Unlocked with the private key: identical to the original.${N}"; fi

# ──────────────────── 4. downgrade attack ────────────────────
title "4. Downgrade attack — the AI tripwire"
FEED="$RUN/connections.jsonl"; : > "$FEED"
bg dashboard env LOG_FILE="$FEED" PORT=$DASH_PORT "$PY" "$ROOT/detector/dashboard.py"
bg feed "$PY" "$ROOT/demo_tools/handshake_feed.py" normal "$FEED"
wait_port "$DASH_PORT"
say "Dashboard: ${B}http://localhost:$DASH_PORT${N}"
note "(Background traffic here is simulated by the detector's generator: the model is trained on"
note " synthetic traffic and does not yet recognise real gateway handshakes. The detector is real.)"
command -v open >/dev/null && (( ! AUTO )) && open "http://localhost:$DASH_PORT" || true
say "Normal traffic is flowing — the banner should be green."
pause
"$PY" "$ROOT/demo_tools/handshake_feed.py" attack "$FEED"
say "An attacker in the middle stripped the quantum-safe options from a client's handshake."
sleep 3
VERDICT="$("$PY" - "$DASH_PORT" <<'EOF'
import json, sys, urllib.request
s = json.load(urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/api/state"))
hit = next((e for e in s["events"] if e["by"] == "rule"), None)
if hit:
    print(f"DASHBOARD: ATTACK DETECTED — {hit['reason']}")
    if hit.get("plain"): print(f"  in plain English: {hit['plain']}")
else:
    print("dashboard has not flagged it yet; check the browser")
EOF
)"
say "${R}${B}${VERDICT}${N}"
pause

# ──────────────────── 5. tamper-evident logs ────────────────────
title "5. Tamper-evident logs — ML-DSA-65 seals"
AUDIT="$RUN/audit_log.jsonl"
tail -n 30 "$FEED" > "$AUDIT"
"$PY" "$ROOT/pqc/qsafe_crypto.py" seal "$AUDIT" | short
"$PY" "$ROOT/pqc/qsafe_crypto.py" verify "$AUDIT"
say ""
say "The attacker edits the log to make their downgrade look like a normal, strong connection:"
"$PY" - "$AUDIT" <<'EOF'
import json, sys
p = sys.argv[1]
lines = open(p).read().splitlines()
for i, l in enumerate(lines):
    n = json.loads(l)
    if not any("MLKEM" in g for g in n["key_groups_offered"]):
        n["key_groups_offered"].insert(0, "X25519MLKEM768"); n["strong_or_weak"] = "strong"
        lines[i] = json.dumps(n)
        print(f"  edited line {i + 1} ({n['client_id']})")
        break
open(p, "w").write("\n".join(lines) + "\n")
EOF
pause
"$PY" "$ROOT/pqc/qsafe_crypto.py" verify "$AUDIT" | short || true

title "Done"
say "Artifacts in run/: captures_direct/, captures_gateway/, bank_records.json.locked, audit_log.jsonl(.seal)"
if (( ! AUTO )); then say "Dashboard still running at http://localhost:$DASH_PORT — press Enter to shut everything down."; read -r _; fi
