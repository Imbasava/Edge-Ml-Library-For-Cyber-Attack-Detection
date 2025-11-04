# Filename: orchestrator.py
# Location: src/network_security_suite/
# PURPOSE: The central brain of the detection suite.

from .models.c2c import C2CModel
# from .models.ddos import DDoSModel # Example of how you'd add more models

class Orchestrator:
    def __init__(self):
        """
        Initializes the Orchestrator and loads all available models.
        """
        print("[Orchestrator] Initializing...")
        self.models = {
            'c2c': C2CModel()
            # 'ddos': DDoSModel() # Future models would be loaded here
        }
        print("[Orchestrator] Initialization complete. Ready for data.")

    def process_flow(self, features: dict) -> dict:
        """
        Processes a single flow of network data.
        This method contains the rule-based logic to decide which model to run.
        """
        
        # ==============================================================
        # 1. RULE-BASED LOGIC (Pre-ML Checks)
        # ==============================================================
        # This is where you can add fast, simple checks to avoid running
        # ML models unnecessarily.
        
        # Example Rule 1: If it's not a TCP or UDP packet, ignore it.
        if features.get('proto') not in ['tcp', 'udp']:
            return {"verdict": "Benign", "reason": "Ignoring non-TCP/UDP protocol"}

        # Example Rule 2: If a TCP connection never established ('S0' state)
        # and lasted less than 2 seconds, it's likely a benign scan, not C2C.
        if features.get('conn_state') == 'S0' and features.get('duration', 0) < 2.0:
             return {"verdict": "Benign", "reason": "Rule-based: Likely a port scan"}
        
        # ==============================================================
        # 2. MODEL INVOCATION
        # ==============================================================
        # If the flow passes the basic rules, we pass it to the ML model.
        # Currently, we only have the C2C model.
        
        # In the future, you could add logic here:
        # if features['total_pkts'] > 1000:
        #     return self.models['ddos'].predict(features)
        # else:
        #     return self.models['c2c'].predict(features)
        
        c2c_result = self.models['c2c'].predict(features)
        
        return c2c_result