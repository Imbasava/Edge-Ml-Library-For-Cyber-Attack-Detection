#!/usr/bin/env python3

# Filename: run_orchestrator.py
# Location: nss_project/ (the root directory)

import os
import json
import sys

# Correct import for the package
from src.network_security_suite.orchestrator import Orchestrator

def main():
    """
    Sequential attack detection: Only loads ML models when traffic patterns
    suggest specific attack types.
    """
    print("[+] Initializing Network Security Suite with Sequential Detection...")
    try:
        project_root = os.path.dirname(os.path.abspath(__file__))
        model_base_path = os.path.join(project_root, 'src', 'trained_models')
        
        orchestrator = Orchestrator(model_base_path=model_base_path)

    except Exception as e:
        print(f"[FATAL] Could not initialize Orchestrator: {e}", file=sys.stderr)
        sys.exit(1)
    
    print("[*] Sequential detection active. Checking: C2C → DDoS → MITM patterns")
    print("[*] ML models will be loaded only when attack patterns are detected")
    
    for line in sys.stdin:
        try:
            flow_data = json.loads(line)
            
            # Process through sequential detection
            result = orchestrator.process_flow(flow_data)
            
            print(json.dumps(result))
            sys.stdout.flush()  # Ensure immediate output

        except json.JSONDecodeError:
            print(f"[Warning] Invalid JSON: {line.strip()}", file=sys.stderr)
            continue
        except Exception as e:
            print(f"[Error] Processing failed: {e}", file=sys.stderr)
            continue

if __name__ == "__main__":
    main()