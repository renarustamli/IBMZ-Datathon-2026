import json
from pathlib import Path

from attack import CAPTURES, crack_session

records = {r["id"]: r for r in json.loads(
    (Path(__file__).parent.parent / "legacy_server" / "records.json").read_text())}
valid = {json.dumps(r, sort_keys=True) for r in records.values()}

files = sorted(CAPTURES.glob("session_*.json"))
for path in files:
    record, _ = crack_session(path)
    assert record is not None, f"{path.name} did not crack"
    assert json.dumps(
        record, sort_keys=True) in valid, f"{path.name} gave wrong data"
print(f"All {len(files)} stolen records match the real data")
