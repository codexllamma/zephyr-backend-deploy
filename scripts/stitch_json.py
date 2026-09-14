#!/usr/bin/env python3
import os
import json

# Define your input files (update paths if necessary)
FILE_1 = "../data/dpo_dataset/preferences.jsonl"               # Your first 1-99 batch
FILE_2 = "../data/dpo_dataset_100_to_300/preferences.jsonl"    # The batch we just recovered
OUTPUT_FILE = "data/final_merged_dpo/preferences.jsonl"     # The final clean file

def merge_and_deduplicate(files, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    unique_incidents = {}
    total_raw_rows = 0

    # 1. Read through all files
    for filepath in files:
        if not os.path.exists(filepath):
            print(f"⚠️  Warning: {filepath} not found. Skipping.")
            continue
            
        print(f"📂 Processing {filepath}...")
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                total_raw_rows += 1
                record = json.loads(line)
                inc_id = record.get("metadata", {}).get("incident_id")
                
                if inc_id:
                    # By assigning to a dictionary, any duplicates are instantly overwritten 
                    # by the most recent entry for that specific incident_id.
                    unique_incidents[inc_id] = record

    # 2. Sort the final dictionary numerically by INC-XXX
    # This ensures your final file goes INC-001, INC-002, sequentially.
    sorted_records = sorted(
        unique_incidents.values(), 
        key=lambda x: int(x["metadata"]["incident_id"].split("-")[1])
    )

    # 3. Write out the clean, deduplicated file
    with open(output_path, "w", encoding="utf-8") as f:
        for record in sorted_records:
            f.write(json.dumps(record) + "\n")

    print("\n✅ Merge Complete!")
    print(f"📊 Total Raw Rows Scanned: {total_raw_rows}")
    print(f"🧹 Final Unique Incidents: {len(sorted_records)}")
    print(f"💾 Saved clean dataset to: {output_path}")

if __name__ == "__main__":
    merge_and_deduplicate([FILE_1, FILE_2], OUTPUT_FILE)