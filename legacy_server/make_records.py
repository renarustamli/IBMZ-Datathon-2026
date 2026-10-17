import json
import random
from pathlib import Path

random.seed(42)  # fixed seed, so everyone gets the same data

FIRST = ["Aarav", "Maya", "Liam", "Sofia", "Noah", "Priya", "Ethan", "Zara",
         "Oliver", "Isha", "Jack", "Amelia", "Kabir", "Freya", "Leo", "Nina",
         "Arjun", "Chloe", "Harry", "Anaya"]
LAST = ["Shah", "Patel", "Smith", "Jones", "Khan", "Taylor", "Brown", "Mehta",
        "Wilson", "Davies", "Singh", "Evans", "Clarke", "Joshi", "Walker"]

NUM_RECORDS = 40

records = []
used_accounts = set()

while len(records) < NUM_RECORDS:
    name = f"{random.choice(FIRST)} {random.choice(LAST)}"
    account = f"{random.randint(10000000, 99999999)}"
    if account in used_accounts:
        continue
    used_accounts.add(account)
    records.append({
        "id": len(records) + 1,
        "name": name,
        "account_number": account,
        "balance": round(random.uniform(100, 50000), 2),
    })

out_path = Path(__file__).parent / "records.json"
out_path.write_text(json.dumps(records, indent=2))
print(f"Wrote {len(records)} records to {out_path}")
