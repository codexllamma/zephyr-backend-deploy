import os
import sys
from rich.console import Console

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app.graph.orchestrator import soc_graph
from app.core.state import IncidentState



console = Console()

def evaluate_incident(incident_id, alert_signature, source_ip, target_ip):
    console.print(f"\n[bold cyan]=== EVALUATING {incident_id} ===[/bold cyan]")
    
    state = IncidentState(
        incident_id=incident_id,
        alert_signature=alert_signature,
        source_ip=source_ip,
        target_ip=target_ip
    )
    
    try:
        raw_output = soc_graph.invoke(state)
        final_state = raw_output if isinstance(raw_output, dict) else raw_output.model_dump()
        
        action = final_state.get('proposed_action', 'NONE')
        target = final_state.get('proposed_target', 'NONE')
        reviewer = final_state.get('reviewer_decision', 'UNKNOWN')
        
        color = "bold green" if reviewer == "APPROVE" else "bold red"
        console.print(f"Action Output: [bold yellow]{action} -> {target}[/bold yellow]")
        console.print(f"Reviewer Gate: [{color}]{reviewer}[/{color}]")
        
        if final_state.get("learned_rule"):
            console.print("[bold red]FAILED:[/bold red] The Reviewer caught a violation and triggered RART.")
        else:
            console.print("[bold green]PASSED:[/bold green] The model outputted a safe, valid action on the first pass.")
            
    except Exception as e:
        console.print(f"[bold red]Execution Error: {e}[/bold red]")

if __name__ == "__main__":
    evaluate_incident(
        incident_id="INC-001",
        alert_signature="ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)",
        source_ip="104.28.15.12",
        target_ip="10.0.1.15"
    )
    
    evaluate_incident(
        incident_id="INC-002",
        alert_signature="ET TROJAN Ransomware File Extension Modification (.lockbit)",
        source_ip="10.0.5.22",
        target_ip="10.0.0.5"
    )