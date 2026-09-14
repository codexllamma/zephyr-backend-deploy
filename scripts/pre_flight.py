#!/usr/bin/env python3
import os
import sys
import json
import importlib
import requests
from dotenv import load_dotenv

# ANSI Colors for terminal output
G = "\033[92m"
Y = "\033[93m"
R = "\033[91m"
C = "\033[96m"
RST = "\033[0m"

load_dotenv()

def print_header(title: str):
    print(f"\n{C}=== {title} ==={RST}")

def check_dependencies():
    print_header("1. DEPENDENCY CHECK")
    deps = ["langchain", "langchain_community", "langchain_ollama", "supabase", "psutil", "dotenv", "pydantic"]
    missing = []
    
    for dep in deps:
        try:
            importlib.import_module(dep)
            print(f"{G}✅ {dep} installed{RST}")
        except ImportError:
            print(f"{R}❌ {dep} MISSING{RST}")
            missing.append(dep)
            
    if missing:
        print(f"\n{R}[!] Please run: pip install {' '.join(missing)}{RST}")
        sys.exit(1)

def check_ollama():
    print_header("2. OLLAMA & MODELS CHECK")
    base_url = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    try:
        response = requests.get(f"{base_url}/api/tags", timeout=3)
        if response.status_code == 200:
            print(f"{G}✅ Ollama server responding at {base_url}{RST}")
            models = [m["name"] for m in response.json().get("models", [])]
            
            # Check for required models
            if any(m.startswith("llama3.1") for m in models):
                print(f"{G}✅ llama3.1 found in VRAM/Disk{RST}")
            else:
                print(f"{Y}⚠️ llama3.1 missing. Run: ollama pull llama3.1{RST}")
                
            if any(m.startswith("all-minilm") for m in models):
                print(f"{G}✅ all-minilm (embeddings) found in VRAM/Disk{RST}")
            else:
                print(f"{Y}⚠️ all-minilm missing. Run: ollama pull all-minilm{RST}")
                
        else:
            print(f"{R}❌ Ollama returned unexpected status: {response.status_code}{RST}")
    except Exception as e:
        print(f"{R}❌ Failed to connect to Ollama: {str(e)}{RST}")
        print(f"{Y}[!] Make sure 'ollama serve' is running in the background.{RST}")

def check_supabase():
    print_header("3. SUPABASE CONNECTION CHECK")
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_SERVICE_KEY")
    
    if not url or not key:
        print(f"{Y}⚠️ Supabase credentials missing in .env. Engine will run in OFFLINE/MOCK mode.{RST}")
        return
        
    try:
        from supabase import create_client
        client = create_client(url, key)
        # Ping the server to check auth
        client.auth.get_session()
        print(f"{G}✅ Supabase authenticated successfully to {url.split('.')[0]}...{RST}")
    except Exception as e:
        print(f"{R}❌ Supabase connection failed: {str(e)}{RST}")

def check_dataset_integrity():
    print_header("4. DATASET & PATH INTEGRITY CHECK")
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.abspath(os.path.join(script_dir, "..", "data"))
    curriculum_file = os.path.join(data_dir, "curriculum.json")
    raw_logs_dir = os.path.join(data_dir, "raw_logs")
    dpo_file = os.path.join(data_dir, "dpo_dataset", "preferences.jsonl")
    
    # 1. Check Data Directory
    if os.path.exists(data_dir):
        print(f"{G}✅ Data directory found: {data_dir}{RST}")
    else:
        print(f"{R}❌ Data directory missing at {data_dir}{RST}")
        return
        
    # 2. Check Curriculum
    curriculum_data = []
    if os.path.exists(curriculum_file):
        try:
            with open(curriculum_file, "r") as f:
                curriculum_data = json.load(f)
            print(f"{G}✅ curriculum.json loaded ({len(curriculum_data)} incidents){RST}")
        except Exception as e:
            print(f"{R}❌ Failed to parse curriculum.json: {e}{RST}")
    else:
        print(f"{R}❌ curriculum.json missing{RST}")
        
    # 3. Check Raw Logs
    if os.path.exists(raw_logs_dir):
        log_files = [f for f in os.listdir(raw_logs_dir) if f.endswith(".txt")]
        print(f"{G}✅ raw_logs folder found ({len(log_files)} syslog files){RST}")
        
        # Cross-reference
        if len(curriculum_data) == len(log_files) and len(log_files) > 0:
            print(f"{G}✅ Dataset alignment perfect (JSON maps 1:1 with Syslogs){RST}")
            
            # Spot check the first log for embedding tags
            first_log = os.path.join(raw_logs_dir, log_files[0])
            with open(first_log, "r") as f:
                if "[CORE]" in f.read():
                    print(f"{G}✅ [CORE] tags detected for pgvector ingestion{RST}")
                else:
                    print(f"{Y}⚠️ No [CORE] tags found in {log_files[0]}. Embeddings may fail.{RST}")
        else:
            print(f"{Y}⚠️ Dataset mismatch: {len(curriculum_data)} JSON entries vs {len(log_files)} Syslogs{RST}")
    else:
        print(f"{R}❌ raw_logs folder missing{RST}")

    # 4. Check DPO append access
    try:
        os.makedirs(os.path.dirname(dpo_file), exist_ok=True)
        with open(dpo_file, "a") as f:
            pass
        print(f"{G}✅ preferences.jsonl is accessible and ready for appending{RST}")
    except Exception as e:
        print(f"{R}❌ Cannot write to DPO file: {e}{RST}")

if __name__ == "__main__":
    check_dependencies()
    check_ollama()
    check_supabase()
    check_dataset_integrity()
    
    print(f"\n{C}============================================={RST}")
    print(f"{G}Pre-Flight complete. If all checks are green, you are clear to launch!{RST}\n")