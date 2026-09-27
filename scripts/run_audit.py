import json
import os

DPO_FILE = "../data/dpo_dataset/preferences.jsonl"
TOTAL_INCIDENTS = 300

present_ids = set()
with open(DPO_FILE, "r", encoding="utf-8") as f:
    for line in f:
        if line.strip():
            record = json.loads(line)
            inc_id = record.get("metadata", {}).get("incident_id")
            if inc_id:
                try:
                    num = int(inc_id.split("-")[1])
                    present_ids.add(num)
                except ValueError:
                    pass

all_expected = set(range(1, TOTAL_INCIDENTS + 1))
missing_ids = sorted(list(all_expected - present_ids))

print(f"📊 Total Present DPO Pairs: {len(present_ids)} / {TOTAL_INCIDENTS}")
print(f"🔍 Missing Incidents Count: {len(missing_ids)}")
print(f"\nMissing Incident IDs:\n{[f'INC-{i:03d}' for i in missing_ids]}")