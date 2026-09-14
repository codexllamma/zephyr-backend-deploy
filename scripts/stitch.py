#!/usr/bin/env python3
import os
import json
from dotenv import load_dotenv
from supabase import create_client, Client

# ==========================================
# 1. CONFIGURATION
# ==========================================
load_dotenv()
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

START_INC = 100
END_INC = 300
BATCH_TAG = f"{START_INC}_to_{END_INC}"

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
CURRICULUM_FILE = os.path.join(DATA_DIR, "curriculum.json")
DPO_FILE = os.path.join(DATA_DIR, f"dpo_dataset_{BATCH_TAG}", "preferences.jsonl")
RUNS_DIR = os.path.join(DATA_DIR, f"training_runs_{BATCH_TAG}")

os.makedirs(os.path.dirname(DPO_FILE), exist_ok=True)
os.makedirs(RUNS_DIR, exist_ok=True)

# ==========================================
# 2. LOAD CURRICULUM
# ==========================================
print("📖 Loading curriculum.json to map Alert Signatures and IPs...")
with open(CURRICULUM_FILE, "r", encoding="utf-8") as f:
    curriculum_data = json.load(f)

curriculum_map = {item.get("incident_id"): item for item in curriculum_data if "incident_id" in item}

# ==========================================
# 3. RECONSTRUCT TELEMETRY MESSAGES
# ==========================================
def reconstruct_trace(alert_sig, src_ip, tgt_ip, ledger_rows):
    """Rebuilds the multi-turn agent conversation from the ledger rows."""
    messages = [
        {"type": "ai", "content": f"Intake complete. Alert {alert_sig} normalized. Awaiting investigation."},
        {"type": "ai", "content": f"Investigator Requirement: Gathering telemetry for Source: {src_ip} and Target: {tgt_ip}."}
    ]
    
    historical_context = ""
    
    for idx, row in enumerate(ledger_rows):
        action = row.get("original_action", "UNKNOWN_ACTION")
        reason = row.get("failure_reason", "")
        rule = row.get("new_rule_learned", "")
        
        is_last = (idx == len(ledger_rows) - 1)
        
        if not is_last:
            messages.append({"type": "ai", "content": f"Defense Strategy: Execute {action}. Justification: Standard Playbook."})
            messages.append({"type": "ai", "content": f"Reviewer REJECT: {reason}"})
            messages.append({"type": "ai", "content": f"RART Policy Mutated: {rule}. Routing back to Defense..."})
            historical_context += f"\n[NEW CRITICAL RULE JUST LEARNED]: {rule}"
        else:
            # The final chosen path
            messages.append({"type": "ai", "content": f"Defense Strategy: Execute TARGETED_RULE on {src_ip}. Justification: {rule}"})
            messages.append({"type": "ai", "content": f"Reviewer APPROVE: {reason}"})
            messages.append({"type": "ai", "content": "[SUCCESS] Applied TARGETED_RULE. Network fabric routing updated successfully."})
            historical_context += f"\n[FINAL CRITICAL RULE]: {rule}"
            
    return messages, historical_context

# ==========================================
# 4. RECOVERY LOGIC
# ==========================================
def recover_batch(start: int, end: int):
    print(f"\n🔍 Stitching DPO pairs & deep Telemetry for INC-{start:03d} to INC-{end:03d}...")
    recovered_count = 0

    for i in range(start, end + 1):
        inc_id = f"INC-{i:03d}"
        
        scenario = curriculum_map.get(inc_id)
        if not scenario:
            continue
            
        alert_sig = scenario.get("alert_signature", "UNKNOWN_ALERT")
        src_ip = scenario.get("source_ip", "UNKNOWN_IP")
        tgt_ip = scenario.get("target_ip", "UNKNOWN_IP")

        # Query all iterations for this incident
        ledger_resp = supabase.table("learning_ledger").select("*").eq("incident_id", inc_id).order("id").execute()
        ledger_rows = ledger_resp.data

        if not ledger_rows:
            continue

        final_row = ledger_rows[-1]
        first_row = ledger_rows[0]
        
        # 4a. Reconstruct the deep trace and historical context
        reconstructed_messages, historical_context = reconstruct_trace(alert_sig, src_ip, tgt_ip, ledger_rows)

        # 4b. Construct DPO Pair (Unchanged)
        prompt_str = (
            f"Alert Signature: {alert_sig}\n"
            f"Source IP: {src_ip}\n"
            f"Target IP: {tgt_ip}\n"
            f"Assessment Outcome: INCONCLUSIVE"
        )
        rejected_str = (
            f"Action: {first_row.get('original_action', 'BLOCK_SOURCE')}\n"
            f"Target: {src_ip}\n"
            f"Failure Context: {first_row.get('failure_reason', 'Failed safety check.')}"
        )
        chosen_str = (
            f"Action: TARGETED_RULE\n"
            f"Target: {src_ip}\n"
            f"Evolved Rule: {final_row.get('new_rule_learned', '')}\n"
            f"Justification: {final_row.get('new_rule_learned', '')}"
        )

        dpo_entry = {
            "prompt": prompt_str,
            "rejected": rejected_str,
            "chosen": chosen_str,
            "metadata": {
                "incident_id": inc_id,
                "timestamp": final_row.get("created_at", ""),
                "simulated_blast_radius": first_row.get('failure_reason', '')
            }
        }

        with open(DPO_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(dpo_entry) + "\n")

        # 4c. Construct Detailed Telemetry
        telemetry_payload = {
            "incident_id": inc_id,
            "status": "COMPLETED",
            "alert_signature": alert_sig,
            "source_ip": src_ip,
            "target_ip": tgt_ip,
            "hypotheses": ["H1: Attack executed.", "H2: Blocked by defenses.", "H3: False positive."],
            "assessment_outcome": "INCONCLUSIVE",
            "textbook_playbook": first_row.get("original_action", ""),
            "historical_context": historical_context,
            "proposed_action": "TARGETED_RULE",
            "proposed_target": src_ip,
            "action_justification": final_row.get("new_rule_learned", ""),
            "reviewer_decision": "APPROVE",
            "reviewer_feedback": final_row.get("failure_reason", ""),
            "learned_rule": final_row.get("new_rule_learned", ""),
            "execution_result": f"[SUCCESS] Applied TARGETED_RULE to {src_ip}.",
            "messages": reconstructed_messages
        }

        incident_folder = os.path.join(RUNS_DIR, inc_id)
        os.makedirs(incident_folder, exist_ok=True)
        telemetry_file = os.path.join(incident_folder, "telemetry.json")
        
        with open(telemetry_file, "w", encoding="utf-8") as f:
            json.dump(telemetry_payload, f, indent=4)
            
        recovered_count += 1

    print(f"\n🎉 Recovery Complete! Successfully stitched {recovered_count} incidents.")
    print(f"📄 Deep Telemetry output to: {RUNS_DIR}")

if __name__ == "__main__":
    recover_batch(START_INC, END_INC)