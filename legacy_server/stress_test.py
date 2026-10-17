import json
from pathlib import Path

from client import fetch

records = {r["id"]: r for r in json.loads(
    (Path(__file__).parent / "records.json").read_text())}

for i in range(20):
    rid = (i % len(records)) + 1
    assert fetch(rid) == records[rid], f"mismatch on record {rid}"
print("20 connections OK")
