import os
import logging
import traceback
from typing import Optional, List, Dict, Any
from supabase.client import Client, create_client
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import SupabaseVectorStore
from dotenv import load_dotenv

load_dotenv()

# Configure highly verbose logging for the memory fabric
logger = logging.getLogger("Zephyr-RAG")
logger.setLevel(logging.INFO)

# 1. Initialize the embedding model natively (CPU-bound for fast, local execution)
try:
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    logger.info("Successfully loaded HuggingFaceEmbeddings (all-MiniLM-L6-v2).")
except Exception as e:
    logger.error(f"Failed to load embedding model: {e}")
    raise e

# 2. Initialize Supabase
supabase_url = os.environ.get("SUPABASE_URL")
supabase_key = os.environ.get("SUPABASE_SERVICE_KEY")

if not supabase_url or not supabase_key:
    raise ValueError("Missing Supabase credentials (SUPABASE_URL, SUPABASE_SERVICE_KEY) in .env")

try:
    supabase_client: Client = create_client(supabase_url, supabase_key)
    logger.info("Supabase client initialized successfully.")
except Exception as e:
    logger.error(f"Failed to initialize Supabase client: {e}")
    raise e

# ==========================================
# RETRIEVERS (These read from the DB fine)
# ==========================================
def get_playbook_retriever(k: int = 1):
    """Phase 1 Retrieval: Retrieves standard baseline SOC procedures."""
    logger.info(f"Initializing Playbook Retriever (k={k})")
    vector_store = SupabaseVectorStore(
        embedding=embeddings,
        client=supabase_client,
        table_name="soc_playbooks",
        query_name="match_soc_playbooks"
    )
    return vector_store.as_retriever(search_kwargs={"k": k})

def get_postmortem_retriever(k: int = 2):
    """Phase 2 Retrieval: Retrieves historically adapted episodic memory."""
    logger.info(f"Initializing Postmortem Retriever (k={k})")
    vector_store = SupabaseVectorStore(
        embedding=embeddings,
        client=supabase_client,
        table_name="incident_postmortems",
        query_name="match_incident_postmortems"
    )
    return vector_store.as_retriever(search_kwargs={"k": k})

# ==========================================
# RAW INSERTS (Bypassing LangChain wrappers)
# ==========================================
def save_learned_policy(incident_id: str, rule: str, target_class: str) -> None:
    """
    Embeds the mutated policy into episodic memory. 
    Uses direct raw Supabase API insertion to completely bypass LangChain bugs.
    """
    logger.info(f"RAG: Attempting to save new learned policy for incident {incident_id}")
    
    try:
        # 1. Manually generate the 384-dimension vector list
        vector = embeddings.embed_query(rule)
        
        # 2. Build the exact payload matching your SQL table
        payload = {
            "incident_id": incident_id,
            "content": rule,
            "metadata": {"incident_id": incident_id, "target_class": target_class},
            "embedding": vector
        }
        
        # 3. Force insert directly via Supabase client
        response = supabase_client.table("incident_postmortems").insert(payload).execute()
        logger.info(f"RAG: Successfully embedded new episodic memory! DB ID: {response.data[0]['id']}")
        
    except Exception as e:
        # If it crashes now, it physically cannot hide the error.
        logger.error(f"RAG: Failed to save learned policy (Raw Error): {repr(e)}")
        logger.error(traceback.format_exc())

def write_learning_ledger(incident_id: str, failed_action: str, blast_radius: str, rule: str) -> None:
    """Relational insert to power the hackathon dashboard."""
    logger.info(f"RAG: Writing to relational learning ledger for {incident_id}")
    try:
        payload = {
            "incident_id": incident_id,
            "original_action": failed_action,
            "failure_reason": blast_radius,
            "new_rule_learned": rule
        }
        response = supabase_client.table("learning_ledger").insert(payload).execute()
        logger.info(f"RAG: Ledger updated successfully. DB ID: {response.data[0]['id']}")
    except Exception as e:
        logger.error(f"RAG: Ledger Write Failed: {repr(e)}")
        logger.error(traceback.format_exc())