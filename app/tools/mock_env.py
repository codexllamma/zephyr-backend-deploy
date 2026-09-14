import os
import json
import logging
import ipaddress
import re
from dotenv import load_dotenv

# LangChain & Pydantic Imports
from langchain_core.tools import tool
from pydantic import BaseModel, Field

# Local JIT Query Imports (Ollama & Supabase)
from langchain_community.vectorstores import SupabaseVectorStore
from langchain_ollama import OllamaEmbeddings
from supabase import create_client, Client

load_dotenv()

# Configure verbose logging for the environment simulator
logger = logging.getLogger("Zephyr-MockEnv")
logger.setLevel(logging.INFO)

# ==========================================
# MASTER ASSET INVENTORY (DYNAMIC LOAD)
# ==========================================
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
INVENTORY_FILE = os.path.join(DATA_DIR, "asset_inventory.json")

def load_inventory() -> dict:
    if not os.path.exists(INVENTORY_FILE):
        logger.error(f"[FATAL] Inventory file missing at {INVENTORY_FILE}. Run generate_dataset.py first.")
        raise FileNotFoundError(f"Missing {INVENTORY_FILE}")
    try:
        with open(INVENTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"[FATAL] Failed to parse asset inventory: {e}")
        raise

ASSET_INVENTORY = load_inventory()

def resolve_asset(ip_string: str) -> dict:
    """Core Engine Router: Validates an IP against the Asset Inventory."""
    # Extract just the raw IP using regex to strip LLM hallucinations like "(Source IP)"
    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', ip_string)
    clean_ip = ip_match.group(0) if ip_match else ip_string

    if clean_ip in ASSET_INVENTORY:
        return ASSET_INVENTORY[clean_ip]
        
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            raise KeyError(f"Pipeline Fatal Error: Internal/Reserved IP {clean_ip} missing from ASSET_INVENTORY.")
        else:
            return {
                "asset_name": "Unknown External Entity", 
                "criticality_tier": 4, 
                "business_function": "Untrusted Public Internet"
            }
    except ValueError:
        return {
            "asset_name": "Non-Standard/MAC Identifier", 
            "criticality_tier": 4, 
            "business_function": "Unregistered Device"
        }

# ==========================================
# RELAXED PYDANTIC SCHEMAS (FOR LLM FEEDBACK)
# ==========================================
class SecurityActionInput(BaseModel):
    action: str = Field(
        description="The exact mitigation action. MUST be one of: BLOCK_SOURCE, ISOLATE_ASSET, DISABLE_ADAPTER, REBOOT_SYSTEM, WIPE_DISK, DELETE_FILE, TARGETED_RULE. Do not write sentences."
    )
    target: str = Field(
        description="The target IP address to apply the action against."
    )

# ==========================================
# SIMULATION TOOLS
# ==========================================

# ==========================================
# SIMULATION TOOLS
# ==========================================

def sanitize_action(action_str: str) -> str:
    """Fuzzy matching interceptor to handle stubborn LLM sentence formatting."""
    act = action_str.upper()
    if "BLOCK" in act: return "BLOCK_SOURCE"
    if "ISOLATE" in act: return "ISOLATE_ASSET"
    if "DISABLE" in act: return "DISABLE_ADAPTER"
    if "REBOOT" in act: return "REBOOT_SYSTEM"
    if "WIPE" in act: return "WIPE_DISK"
    if "DELETE" in act: return "DELETE_FILE"
    if "RULE" in act or "MITIGAT" in act: return "TARGETED_RULE"
    return action_str

@tool
def check_vulnerability(ip: str) -> str:
    """Check if the target IP has known vulnerabilities via mocked vulnerability scanner."""
    logger.info(f"Tool Execution: check_vulnerability(ip={ip})")
    if ip == "10.0.1.15": 
        return f"[{ip}] CVE-2021-44228 (Log4Shell): Target application is highly vulnerable."
    return f"[{ip}] No known critical vulnerabilities found."

@tool
def check_server_logs(incident_id: str) -> str:
    """Retrieve raw server logs associated with the incident via live Supabase Vector Search."""
    logger.info(f"Tool Execution: check_server_logs(incident_id={incident_id})")
    try:
        supabase_url = os.environ.get("SUPABASE_URL")
        supabase_key = os.environ.get("SUPABASE_SERVICE_KEY")
        if not supabase_url or not supabase_key: return "[ERROR] Supabase credentials missing."
        
        supabase: Client = create_client(supabase_url, supabase_key)
        embeddings = OllamaEmbeddings(model="all-minilm", base_url=os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434"))
        vector_store = SupabaseVectorStore(client=supabase, embedding=embeddings, table_name="server_logs", query_name="match_server_logs")
        
        docs = vector_store.similarity_search(query="Extract malicious telemetry", filter={"incident_id": incident_id}, k=1)
        if docs: return docs[0].metadata.get("full_timeline", "Timeline missing in metadata.")
        return f"[ERROR] No SIEM logs found for {incident_id}."
    except Exception as e:
        return f"[ERROR] SIEM query failed: {str(e)}"

@tool(args_schema=SecurityActionInput)
def simulate_blast_radius(action: str, target: str) -> str:
    """
    Near-Miss Simulation: Run by the Reviewer agent to test a proposed action against the CMDB topology.
    Acts as the deterministic RART guardrail.
    """
    logger.info(f"Tool Execution: simulate_blast_radius(action={action}, target={target})")
    
    # INTERCEPT & SANITIZE
    clean_action = sanitize_action(action)
    
    valid_actions = ["BLOCK_SOURCE", "ISOLATE_ASSET", "DISABLE_ADAPTER", "REBOOT_SYSTEM", "WIPE_DISK", "DELETE_FILE", "TARGETED_RULE"]
    if clean_action not in valid_actions:
        return f"[REJECTED] [FORMAT ERROR] Action '{clean_action}' is invalid."

    infra = resolve_asset(target)
    tier = infra["criticality_tier"]
    
    if tier == 1:
        if clean_action in ["BLOCK_SOURCE", "ISOLATE_ASSET", "DISABLE_ADAPTER", "REBOOT_SYSTEM"]:
            return f"[REJECTED] Target is Tier 1 ({infra['asset_name']}). Proposed action '{clean_action}' violates availability SLA. Suggest granular API revocation, WAF targeting, or failover first."
        return f"[APPROVED] Action '{clean_action}' passes Tier 1 safety checks."
            
    elif tier == 2:
        if clean_action in ["REBOOT_SYSTEM", "WIPE_DISK", "DELETE_FILE"]:
            return f"[REJECTED] Target is Tier 2 ({infra['asset_name']}). Proposed action '{clean_action}' violates data persistence constraints."
        return f"[APPROVED] Action '{clean_action}' passes Tier 2 safety checks."
            
    elif tier >= 3:
        return f"[APPROVED] Action '{clean_action}' safely executed against Tier {tier} entity ({infra['asset_name']}). Zero critical blast radius."

@tool(args_schema=SecurityActionInput)
def execute_firewall_change(action: str, target: str) -> str:
    """Production Execution: Commits the approved action to the network fabric."""
    logger.info(f"Tool Execution: execute_firewall_change(action={action}, target={target})")
    clean_action = sanitize_action(action)
    return f"[SUCCESS] Applied {clean_action} to {target}. Network fabric routing updated successfully."

@tool
def verify_network_traffic(target: str) -> str:
    """Production Execution: Verifies if malicious outbound beaconing or exploitation has ceased."""
    logger.info(f"Tool Execution: verify_network_traffic(target={target})")
    return f"[VERIFIED] No further malicious egress or lateral movement traffic observed on {target}. Connections reset."

soc_tools = [check_vulnerability, check_server_logs, simulate_blast_radius, execute_firewall_change, verify_network_traffic]