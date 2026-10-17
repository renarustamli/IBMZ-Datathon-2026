"""Live green/red dashboard: tails a connection-note log through the Detector.

  python dashboard.py                                   -> http://localhost:5000
  LOG_FILE=../logs/connections.jsonl python dashboard.py   (gateway's real log — the demo)

The model is trained on logs/normal_traffic.jsonl at startup (run generate_traffic.py once).
For a demo without the gateway: `python generate_traffic.py --live` in another terminal.
"""
import json
import os
import threading
import time
from collections import Counter, deque

from flask import Flask, jsonify, render_template

from detector import Detector, LOGS
from explain import explain
from schema import read_notes, normalize

LOG_FILE = os.environ.get("LOG_FILE", os.path.join(LOGS, "connections.jsonl"))
TRAIN_FILE = os.environ.get("TRAIN_FILE", os.path.join(LOGS, "normal_traffic.jsonl"))
RED_WINDOW = 20  # banner stays red while any of the last N connections alerted

app = Flask(__name__)
lock = threading.Lock()
recent = deque(maxlen=200)
counts = Counter()
detector = Detector().train(read_notes(TRAIN_FILE))
detector.reset()  # live clients are judged on their own history, not the training clients'


def tail():
    """Follow LOG_FILE like `tail -F`: start from the top, handle truncation/rotation."""
    pos, inode = 0, None
    while True:
        try:
            st = os.stat(LOG_FILE)
        except FileNotFoundError:
            time.sleep(1)
            continue
        if st.st_ino != inode or st.st_size < pos:
            pos, inode = 0, st.st_ino
            with lock:
                detector.reset(); recent.clear(); counts.clear()
        with open(LOG_FILE) as f:
            f.seek(pos)
            while True:
                line = f.readline()
                if not line.endswith("\n"):
                    break  # partial line still being written; retry next round
                pos = f.tell()
                if not line.strip():
                    continue
                try:
                    note = normalize(json.loads(line))
                    r = detector.check(note)
                    r["plain"] = explain(note, r)
                except Exception as e:  # a malformed note must not kill the feed
                    note, r = {"raw": line.strip()}, {"alert": False, "by": None, "reason": f"unparsed: {e}", "score": 0, "plain": ""}
                with lock:
                    recent.append({**note, **r})
                    counts["total"] += 1
                    counts["strong"] += note.get("strong_or_weak") == "strong"
                    if r["by"]:
                        counts[r["by"]] += 1
        time.sleep(0.5)


@app.route("/")
def index():
    return render_template("dashboard.html", log_file=os.path.relpath(LOG_FILE))


@app.route("/api/state")
def state():
    with lock:
        events = list(recent)[::-1]
        c = dict(counts)
    under_attack = any(e["alert"] for e in events[:RED_WINDOW])
    return jsonify(under_attack=under_attack, counts=c, events=events[:100],
                   threshold=detector.threshold)


if __name__ == "__main__":
    threading.Thread(target=tail, daemon=True).start()
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)))
