"""Log-integrity tile: checks the connection log against B's ML-DSA seals (pqc/qsafe_crypto.py).

Optional: if the crypto layer, its keys, or the .seal file are missing, the tile just says so
and the detector works as before.

  QSAFE_DIR   folder holding qsafe_crypto.py   (default: ../pqc next to /detector)
  QSAFE_KEYS  folder holding the keys          (default: $QSAFE_DIR/keys)
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
QSAFE_DIR = os.environ.get("QSAFE_DIR", os.path.join(HERE, "..", "pqc"))
os.environ.setdefault("QSAFE_KEYS", os.path.join(QSAFE_DIR, "keys"))

PENDING = "line was added after sealing"  # the sealer follows the log, so the newest lines lag

try:
    sys.path.insert(0, QSAFE_DIR)
    from qsafe_crypto import verify_log
    IMPORT_ERROR = None
except BaseException as e:  # qsafe_crypto raises SystemExit when its libraries are missing
    verify_log, IMPORT_ERROR = None, str(e) or type(e).__name__


def check(log_file):
    """-> {"status": ok | tampered | pending | unavailable, "lines": n, "detail": str}"""
    if verify_log is None:
        return {"status": "unavailable", "lines": 0, "detail": f"crypto layer not found ({IMPORT_ERROR})"}
    if not os.path.exists(log_file):
        return {"status": "unavailable", "lines": 0, "detail": "no log yet"}
    try:
        r = verify_log(log_file)
    except Exception as e:  # missing keys, unreadable seal file, ...
        return {"status": "unavailable", "lines": 0, "detail": str(e)}
    problems = r["problems"]
    if r["ok"]:
        return {"status": "ok", "lines": r["lines"], "detail": "every line signed with ML-DSA-65"}
    if problems and problems[0][0] == 0:  # line 0 = whole-file problem, e.g. never sealed
        return {"status": "unavailable", "lines": r["lines"], "detail": problems[0][1]}
    if all(reason == PENDING for _, reason in problems):
        return {"status": "pending", "lines": r["lines"], "detail": f"{len(problems)} newest line(s) awaiting seal"}
    line, reason = next((n, why) for n, why in problems if why != PENDING)
    return {"status": "tampered", "lines": r["lines"], "detail": f"line {line}: {reason}"}
