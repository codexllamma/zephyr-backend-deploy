#!/usr/bin/env python3
import os
import sys
import json
from dotenv import load_dotenv
from rich.console import Console
import langchain

# LangChain & Supabase JIT Ingestion Imports
from langchain_core.documents import Document
from langchain_community.vectorstores import SupabaseVectorStore
from langchain_ollama import OllamaEmbeddings
from supabase import create_client, Client

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app.graph.orchestrator import soc_graph
from app.core.state import IncidentState

load_dotenv()
console = Console()
langchain.verbose = True

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
CURRICULUM_FILE = os.path.join(DATA_DIR, "curriculum.json")
RAW_LOGS_DIR = os.path.join(DATA_DIR, "raw_logs")

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
        metadata={"incident_id": incident_id, "document_type": "raw_syslog", "full_timeline": full_content}
    )
    
    # Matches your 384-dimension SQL schema
    embeddings = OllamaEmbeddings(
        model="all-minilm",
        base_url=os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    )
    SupabaseVectorStore.from_documents(
        [doc], embeddings, client=supabase_client, 
        table_name="server_logs", 
        query_name="match_server_logs"
    )

def main():
    console.print("[bold cyan]=== ZEPHYR GYM: SINGLE TEST RUN ===[/bold cyan]")
    
    supabase_url = os.environ.get("SUPABASE_URL")
    supabase_key = os.environ.get("SUPABASE_SERVICE_KEY")
    supabase_client = create_client(supabase_url, supabase_key) if supabase_url and supabase_key else None

    with open(CURRICULUM_FILE, "r", encoding="utf-8") as f:
        curriculum = json.load(f)
    
    with open(CURRICULUM_FILE, "r", encoding="utf-8") as f:
        curriculum = json.load(f)
    
   
    scenario = curriculum[12]
    incident_id = scenario.get("incident_id")
    signature = scenario.get("alert_signature", "UNKNOWN_ALERT")
    
    incident_id = scenario.get("incident_id")
    signature = scenario.get("alert_signature", "UNKNOWN_ALERT")
    
    console.print(f"[bold yellow]1. Ingesting Telemetry for {incident_id}...[/bold yellow]")
    ingest_single_incident(incident_id, supabase_client)
    
    console.print(f"[bold yellow]2. Initializing LangGraph for {incident_id}...[/bold yellow]")
    initial_state = IncidentState(
        incident_id=incident_id,
        alert_signature=signature,
        source_ip=scenario.get("source_ip", "0.0.0.0"),
        target_ip=scenario.get("target_ip", "0.0.0.0")
    )
    
    raw_output = soc_graph.invoke(initial_state)
    final_state = raw_output if isinstance(raw_output, dict) else raw_output.model_dump()
    
    # Strip complex LangChain message objects for clean console output
    if "messages" in final_state:
        del final_state["messages"]
        
    console.print("\n[bold green]=== TEST RUN COMPLETE - FINAL STATE ===[/bold green]")
    console.print_json(data=final_state)
    
    if final_state.get("learned_rule"):
        console.print(f"\n[bold magenta]RART Triggered! Learned Rule:[/bold magenta] {final_state['learned_rule']}")
    else:
        console.print("\n[bold blue]No rule evolution required. Action approved on first pass.[/bold blue]")

if __name__ == "__main__":
    main()