# Filename: run_orchestrator.py
# Location: / (root of the project)
# PURPOSE: The main entry point for the live detection pipeline.

import sys
import json

# ABSOLUTE import - no dots at the beginning
from src.network_security_suite.orchestrator import Orchestrator

def main():
    """
    Main function to run the detection pipeline.
    It reads JSON data from standard input (piped from the C++ producer),
    sends it to the orchestrator, and prints the result.
    """
    try:
        orchestrator = Orchestrator()
    except Exception as e:
        print(f"FATAL: Could not initialize the Orchestrator. Shutting down. Error: {e}", file=sys.stderr)
        return
    
    # Continuously read from stdin
    for line in sys.stdin:
        try:
            # Trim whitespace and parse the JSON line
            flow_features = json.loads(line.strip())
            
            # Get the verdict from the orchestrator
            result = orchestrator.process_flow(flow_features)
            
            # Print the result as a JSON string to stdout
            # This makes it easy for other programs to consume the output
            print(json.dumps(result))
            
        except json.JSONDecodeError:
            # Handle cases where the C++ producer might output a non-JSON line
            print(f"Warning: Received a non-JSON line: {line.strip()}", file=sys.stderr)
            continue
            
        except Exception as e:
            # Catch any other errors during processing
            print(f"Error processing features: {line.strip()}. Details: {e}", file=sys.stderr)
            continue

if __name__ == "__main__":
    main()