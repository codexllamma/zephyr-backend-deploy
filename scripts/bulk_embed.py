#!/usr/bin/env python3
import os
import sys
import json
from dotenv import load_dotenv

from langchain_core.documents import Document
from langchain_community.vectorstores import SupabaseVectorStore
from langchain_ollama import OllamaEmbeddings
from supabase import create_client

load_dotenv()

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
CURRICULUM_FILE = os.path.join(DATA_DIR, "curriculum.json")
RAW_LOGS_DIR = os.path.join(DATA_DIR, "raw_logs")

def main():
    print("\n🚀 Starting Bulletproof Bulk Ingestion (Runs 101-500)...")
    
    supabase_url = os.environ.get("SUPABASE_URL")
    supabase_key = os.environ.get("SUPABASE_SERVICE_KEY")
    if not supabase_url or not supabase_key:
        print("❌ Missing Supabase credentials in .env")
        sys.exit(1)
        
    supabase_client = create_client(supabase_url, supabase_key)
    
    # Verify Ollama is actually responding before looping
    try:
        embeddings = OllamaEmbeddings(
            model="all-minilm", 
            base_url=os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        )
        # Test generation
        embeddings.embed_query("test")
    except Exception as e:
        print(f"❌ Ollama/all-minilm connection failed: {e}")
        sys.exit(1)
    
    with open(CURRICULUM_FILE, "r", encoding="utf-8") as f:
        curriculum = json.load(f)
        
    START_IDX = 0
    active_batch = curriculum[START_IDX:]
    
    print(f"📦 Processing {len(active_batch)} incidents...")
    
    success_count = 0
    
    for idx, scenario in enumerate(active_batch, start=START_IDX + 1):
        incident_id = scenario.get("incident_id")
        log_path = os.path.join(RAW_LOGS_DIR, f"{incident_id}_syslog.txt")
        
        if not os.path.exists(log_path):
            print(f"⚠️ [Run {idx}] SKIPPED: File missing -> {incident_id}_syslog.txt")
            continue
            
        with open(log_path, "r", encoding="utf-8") as f:
            full_content = f.read()
            
        # FIXED: Use 'in line' instead of 'startswith' to catch [CORE] anywhere in the string
        core_lines = [line.strip() for line in full_content.split("\n") if "[CORE]" in line]
        
        if not core_lines:
            print(f"⚠️ [Run {idx}] SKIPPED {incident_id}: No [CORE] tags found inside the file.")
            continue
            
        doc = Document(
            page_content="\n".join(core_lines),
            metadata={
                "incident_id": incident_id,
                "document_type": "raw_syslog",
                "full_timeline": full_content
            }
        )
        
        try:
            SupabaseVectorStore.from_documents(
                [doc],
                embeddings,
                client=supabase_client,
                table_name="server_logs",
                query_name="match_server_logs"
            )
            print(f"✅ [Run {idx}] Embedded and uploaded: {incident_id}")
            success_count += 1
        except Exception as e:
            # This will catch Supabase schema errors, network drops, or vector mismatches
            print(f"❌ [Run {idx}] SUPABASE REJECTED {incident_id}: {str(e)}")
            
    print(f"\n🎉 Bulk ingestion complete! Successfully inserted {success_count} / {len(active_batch)} records.")

if __name__ == "__main__":
    main()