#!/usr/bin/env python3
import os
import sys
import json
import time
import uuid
import shutil
import psutil
import requests
from datetime import datetime
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv

from pydantic import BaseModel, Field

# LangChain & Supabase JIT Ingestion Imports
from langchain_core.documents import Document
from langchain_community.vectorstores import SupabaseVectorStore
from langchain_ollama import OllamaEmbeddings
import langchain

# Ensure application modules can be discovered from scripts directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.graph.orchestrator import soc_graph
from app.core.state import IncidentState

# Optional cloud storage client
try:
    from supabase import create_client, Client
    SUPABASE_AVAILABLE = True
except ImportError:
    SUPABASE_AVAILABLE = False

load_dotenv()

import logging

# Configure background logging to capture all agent/tool activity
DEBUG_LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "zephyr_debug.log")
logging.basicConfig(
    filename=DEBUG_LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

# Optional: Force LangChain to write its internal execution traces to the logger
langchain.verbose = True

# ==========================================
# 1. CONSTANTS & PATHS
# ==========================================

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
CURRICULUM_FILE = os.path.join(DATA_DIR, "curriculum.json")
RAW_LOGS_DIR = os.path.join(DATA_DIR, "raw_logs")
DPO_FILE = os.path.join(DATA_DIR, "dpo_dataset", "preferences.jsonl")
RUNS_DIR = os.path.join(DATA_DIR, "training_runs")

# INTERMEDIARY BACKUPS DISABLED
BACKUP_INTERVAL_SECONDS = 9999999  
THROTTLE_CPU_PERCENT = 95.0
THROTTLE_RAM_PERCENT = 95.0
THROTTLE_TEMP_C = 90.0
COOLING_CYCLE_SECONDS = 15 # Extended for robust local cooling

# ==========================================
# 2. PRE-FLIGHT VALIDATION & SERVICE CHECKS
# ==========================================

def verify_ollama_running() -> None:
    print("\n⚙️  Verifying Ollama Service...")
    base_url = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    try:
        response = requests.get(f"{base_url}/api/tags", timeout=5)
        if response.status_code == 200:
            print("✅ Ollama is online and responding.")
        else:
            print(f"❌ Ollama returned unexpected status: {response.status_code}")
            sys.exit(1)
    except Exception as e:
        print(f"❌ FATAL: Cannot connect to Ollama at {base_url}. Is the service running?\nError: {e}")
        sys.exit(1)

def verify_supabase_connection(client: Client) -> None:
    print("\n⚙️  Verifying Supabase Connection...")
    if not client:
        print("⚠️  Supabase client not initialized (missing env vars). Operating in MOCK/OFFLINE mode.")
        return
    try:
        # Lightweight check to ensure client is authenticated
        client.auth.get_session()
        print("✅ Supabase connection established.")
    except Exception as e:
        print(f"❌ FATAL: Supabase authentication or connection failed.\nError: {e}")
        sys.exit(1)

def pre_flight_check(curriculum: List[Dict[str, Any]]) -> None:
    print("\n=== EXECUTING PRE-FLIGHT DATASET VALIDATION ===")
    
    if not os.path.exists(RAW_LOGS_DIR):
        print(f"[FATAL] RAW_LOGS_DIR missing at {RAW_LOGS_DIR}")
        sys.exit(1)
        
    log_files = [f for f in os.listdir(RAW_LOGS_DIR) if f.endswith(".txt")]
    
    if len(curriculum) != len(log_files):
        print(f"[FATAL] Dataset Drift Detected: {len(curriculum)} JSON entries vs {len(log_files)} syslog files.")
        sys.exit(1)
        
    for entry in curriculum:
        inc_id = entry.get("incident_id")
        if not inc_id:
            print("[FATAL] Malformed curriculum JSON: Missing incident_id.")
            sys.exit(1)
            
        log_path = os.path.join(RAW_LOGS_DIR, f"{inc_id}_syslog.txt")
        if not os.path.exists(log_path):
            print(f"[FATAL] Broken Link: curriculum.json contains {inc_id} but {inc_id}_syslog.txt is missing.")
            sys.exit(1)
            
    print("✅ Pre-Flight Validation Passed. Dataset is structurally and semantically intact.\n")
    time.sleep(1)

def setup_directories() -> None:
    os.makedirs(os.path.dirname(DPO_FILE), exist_ok=True)
    os.makedirs(RUNS_DIR, exist_ok=True)

def load_curriculum() -> List[Dict[str, str]]:
    if not os.path.exists(CURRICULUM_FILE):
        print(f"[!] Critical Error: Curriculum file not found at {CURRICULUM_FILE}")
        sys.exit(1)
    try:
        with open(CURRICULUM_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, list):
                raise ValueError("Curriculum must be a JSON array of objects.")
            return data
    except Exception as e:
        print(f"[!] Failed to parse curriculum JSON: {e}")
        sys.exit(1)

def backup_to_supabase(supabase_client: Client) -> None:
    if not supabase_client:
        return
    try:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        zip_filename = f"zephyr_logs_{timestamp}"
        archive_path = os.path.join(DATA_DIR, zip_filename)

        shutil.make_archive(archive_path, 'zip', DATA_DIR)
        full_zip_path = f"{archive_path}.zip"

        with open(full_zip_path, "rb") as f:
            supabase_client.storage.from_("training_logs").upload(
                path=f"{zip_filename}.zip",
                file=f,
                file_options={"content-type": "application/zip"}
            )
        if os.path.exists(full_zip_path):
            os.remove(full_zip_path)
        print(f"✅ Cloud backup successful: {zip_filename}.zip")
    except Exception as e:
        print(f"⚠️ Autonomous cloud backup skipped: {str(e)}")

# ==========================================
# 3. JUST-IN-TIME (JIT) TELEMETRY INGESTION
# ==========================================

def ingest_single_incident(incident_id: str, supabase_client: Client) -> None:
    if not supabase_client:
        return

    log_path = os.path.join(RAW_LOGS_DIR, f"{incident_id}_syslog.txt")
    
    with open(log_path, "r", encoding="utf-8") as f:
        full_content = f.read()

    core_lines = [line.strip() for line in full_content.split("\n") if line.startswith("[CORE]")]
    if not core_lines:
        return

    doc = Document(
        page_content="\n".join(core_lines),
        metadata={
            "incident_id": incident_id,
            "document_type": "raw_syslog",
            "full_timeline": full_content
        }
    )

    try:
        embeddings = OllamaEmbeddings(
            model="all-minilm", 
            base_url=os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        )
        SupabaseVectorStore.from_documents(
            [doc],
            embeddings,
            client=supabase_client,
            table_name="server_logs",
            query_name="match_server_logs"
        )
    except Exception as e:
        print(f"[!] Failed to embed telemetry for {incident_id}: {str(e)}")

# ==========================================
# 4. TELEMETRY SERIALIZATION & HARVESTING
# ==========================================

def clean_state_for_json(raw_state: Dict[str, Any]) -> Dict[str, Any]:
    serialized = {}
    for key, value in raw_state.items():
        if key == "messages" and isinstance(value, list):
            serialized[key] = [
                {"type": getattr(msg, "type", "message"), "content": getattr(msg, "content", str(msg))}
                for msg in value
            ]
        elif isinstance(value, (str, int, float, bool, list, dict)) or value is None:
            serialized[key] = value
        else:
            serialized[key] = str(value)
    return serialized

def log_dpo_preference(final_state: Dict[str, Any]) -> None:
    prompt_str = (
        f"Alert Signature: {final_state.get('alert_signature', '')}\n"
        f"Source IP: {final_state.get('source_ip', '')}\n"
        f"Target IP: {final_state.get('target_ip', '')}\n"
        f"Assessment Outcome: {final_state.get('assessment_outcome', '')}"
    )
    rejected_str = (
        f"Action: BLOCK_SOURCE\n"
        f"Target: {final_state.get('source_ip', '')}\n"
        f"Failure Context: {final_state.get('reviewer_feedback', 'Failed blast-radius simulation')}"
    )
    chosen_str = (
        f"Action: {final_state.get('proposed_action', 'ISOLATE_ASSET')}\n"
        f"Target: {final_state.get('proposed_target', '')}\n"
        f"Evolved Rule: {final_state.get('learned_rule', '')}\n"
        f"Justification: {final_state.get('action_justification', '')}"
    )
    dpo_entry = {
        "prompt": prompt_str,
        "rejected": rejected_str,
        "chosen": chosen_str,
        "metadata": {
            "incident_id": final_state.get("incident_id"),
            "timestamp": datetime.utcnow().isoformat(),
            "simulated_blast_radius": final_state.get("simulated_blast_radius", "")
        }
    }
    # Enforcing strict append mode
    with open(DPO_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(dpo_entry) + "\n")

def save_run_telemetry(incident_id: str, raw_state: Dict[str, Any]) -> None:
    incident_folder = os.path.join(RUNS_DIR, incident_id)
    os.makedirs(incident_folder, exist_ok=True)
    telemetry_file = os.path.join(incident_folder, "telemetry.json")

    cleaned_data = clean_state_for_json(raw_state)
    with open(telemetry_file, "w", encoding="utf-8") as f:
        json.dump(cleaned_data, f, indent=4)

# ==========================================
# 5. HARDWARE MONITORING & COOLING
# ==========================================

def get_system_temp() -> float:
    try:
        temps = psutil.sensors_temperatures()
        if not temps:
            return 0.0
        core_readings = [entry.current for entry in list(temps.values())[0]]
        return sum(core_readings) / len(core_readings) if core_readings else 0.0
    except (AttributeError, KeyError, IndexError):
        return 0.0

def check_hardware_limits(run_idx: int) -> bool:
    cpu_usage = psutil.cpu_percent(interval=0.2)
    ram_usage = psutil.virtual_memory().percent
    temp_c = get_system_temp()

    is_overheated = temp_c > THROTTLE_TEMP_C and temp_c != 0.0
    is_overloaded = cpu_usage > THROTTLE_CPU_PERCENT or ram_usage > THROTTLE_RAM_PERCENT

    if is_overheated or is_overloaded:
        print(f"\n⚠️  [THROTTLE] Hardware limits exceeded. CPU: {cpu_usage}% | RAM: {ram_usage}% | Temp: {temp_c}°C")
        print(f"❄️  Initiating {COOLING_CYCLE_SECONDS}-second cooling pause...")
        time.sleep(COOLING_CYCLE_SECONDS)
        return True
    return False

# ==========================================
# 6. DASHBOARD INTERFACE (Standard Console)
# ==========================================

def format_time(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"

# ==========================================
# 7. MAIN GYM EXECUTION ENGINE
# ==========================================

def main() -> None:
    setup_directories()
    
    # Run environment checks
    verify_ollama_running()
    
    supabase_url = os.environ.get("SUPABASE_URL")
    supabase_key = os.environ.get("SUPABASE_SERVICE_KEY")
    supabase_client = create_client(supabase_url, supabase_key) if SUPABASE_AVAILABLE and supabase_url and supabase_key else None
    
    verify_supabase_connection(supabase_client)
    
    curriculum = load_curriculum()
    total_runs = len(curriculum)
    pre_flight_check(curriculum)
    
    dpo_count = 0
    last_backup_timestamp = time.time()
    
    # ==========================================
    # DETERMINISTIC RESUME LOGIC
    # ==========================================
    START_RUN = 126
    active_curriculum = curriculum[(START_RUN - 1):]
    
    start_time = time.time()
    
    print(f"\n🚀 IGNITION: Starting Zephyr Gym from Run {START_RUN} of {total_runs}...\n")

    for idx, scenario in enumerate(active_curriculum, start=START_RUN):
        incident_id = scenario.get("incident_id", f"INC-GYM-{uuid.uuid4().hex[:6].upper()}")
        signature = scenario.get("alert_signature", "UNKNOWN_ALERT")
        
        # Monitor limits and cool down if needed
        check_hardware_limits(idx)

        elapsed = time.time() - start_time
        avg_time = elapsed / max(1, idx - START_RUN) if idx > START_RUN else 0
        eta = avg_time * (total_runs - idx + 1) if avg_time else 0
        
        print(f"[{format_time(elapsed)} | ETA: {format_time(eta)}] RUN {idx}/{total_runs} | {incident_id}")
        
        ingest_single_incident(incident_id, supabase_client)

        initial_state = IncidentState(
            incident_id=incident_id,
            alert_signature=signature,
            source_ip=scenario.get("source_ip", "0.0.0.0"),
            target_ip=scenario.get("target_ip", "0.0.0.0")
        )

        try:
            raw_output = soc_graph.invoke(initial_state)
            final_state = raw_output if isinstance(raw_output, dict) else raw_output.model_dump()

            save_run_telemetry(incident_id, final_state)

            learned_rule = final_state.get("learned_rule")
            rart_active = bool(learned_rule and str(learned_rule).strip() != "")

            if rart_active:
                log_dpo_preference(final_state)
                dpo_count += 1

            reviewer_decision = final_state.get("reviewer_decision", "UNKNOWN")
            action = f"{final_state.get('proposed_action', 'NONE')} -> {final_state.get('proposed_target', '')}"
            
            print(f" ↳ ✅ Completed | Gate: {reviewer_decision} | RART Mutated: {rart_active} | Action: {action}")

        except Exception as ex:
            print(f" ↳ ❌ FAILED: {str(ex)[:100]}")

        current_timestamp = time.time()
        if current_timestamp - last_backup_timestamp > BACKUP_INTERVAL_SECONDS:
            print(" ↳ ☁️ Uploading intermediary backup to Supabase...")
            backup_to_supabase(supabase_client)
            last_backup_timestamp = time.time()

    print(f"\n🎉 Curriculum exhausted. Script executed in {format_time(time.time() - start_time)}.")
    print(f"📊 Total DPO preference entries logged this session: {dpo_count}")
    print("☁️ Uploading final state snapshot to Supabase 'training_logs'...")
    backup_to_supabase(supabase_client)
    print("✅ System offline and ready for evaluation.")

if __name__ == "__main__":
    main()