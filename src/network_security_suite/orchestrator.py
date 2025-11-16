# Filename: orchestrator.py
# Location: src/network_security_suite/
# PURPOSE: Sequential attack detection with data type awareness.

import os
import sys
from typing import Dict, Any

class Orchestrator:
    """
    Sequential attack detector with data type awareness.
    First identifies data type, then applies relevant rules.
    """
    def __init__(self, model_base_path: str):
        self.model_base_path = model_base_path
        self.models = {}
        print("[*] Orchestrator initialized with data-type-aware sequential detection")

    def _identify_data_type(self, flow_data: Dict[str, Any]) -> str:
        """
        Identify the data type based on structure before applying rules.
        Returns: 'c2c', 'ddos', 'mitm', or 'unknown'
        """
        # Check for C2C data structure
        if all(key in flow_data for key in ['proto', 'service', 'duration', 'orig_bytes', 'resp_bytes']):
            return 'c2c'
        
        # Check for DDoS data structure
        if 'features' in flow_data and isinstance(flow_data['features'], dict):
            ddos_features = flow_data['features']
            if all(key in ddos_features for key in ['Packets_Per_Sec', 'Bytes_Per_Sec', 'Unique_IPs']):
                return 'ddos'
        
        # Check for MITM data structure
        if 'features' in flow_data and isinstance(flow_data['features'], list) and 'ip_address' in flow_data:
            return 'mitm'
        
        return 'unknown'

    def _load_c2c_model(self):
        """Load C2C model only when needed"""
        if 'c2c' not in self.models:
            try:
                from .models.c2c import C2CModel
                model_path = os.path.join(self.model_base_path, 'c2c')
                self.models['c2c'] = C2CModel(model_path=model_path)
                print("✓ C2C model loaded")
            except Exception as e:
                print(f"⚠ Failed to load C2C model: {e}")
                return None
        return self.models['c2c']

    def _load_ddos_model(self):
        """Load DDoS model only when needed"""
        if 'ddos' not in self.models:
            try:
                from .models.ddos import DDoSModel
                model_path = os.path.join(self.model_base_path, 'ddos')
                self.models['ddos'] = DDoSModel(model_path=model_path)
                print("✓ DDoS model loaded")
            except Exception as e:
                print(f"⚠ Failed to load DDoS model: {e}")
                return None
        return self.models['ddos']

    def _load_mitm_model(self):
        """Load MITM model only when needed"""
        if 'mitm' not in self.models:
            try:
                from .models.mitm import MITMModel
                model_path = os.path.join(self.model_base_path, 'mitm')
                self.models['mitm'] = MITMModel(model_path=model_path)
                print("✓ MITM model loaded")
            except Exception as e:
                print(f"⚠ Failed to load MITM model: {e}")
                return None
        return self.models['mitm']

    def process_flow(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Data-type-aware sequential detection:
        1. Identify data type first
        2. Only check rules for that specific data type
        3. Load model only if rules match
        """
        data_type = self._identify_data_type(flow_data)
        print(f"[*] Identified data type: {data_type}")

        if data_type == 'c2c':
            return self._process_c2c_data(flow_data)
        elif data_type == 'ddos':
            return self._process_ddos_data(flow_data)
        elif data_type == 'mitm':
            return self._process_mitm_data(flow_data)
        else:
            return {
                "verdict": "UNKNOWN",
                "attack_type": "None",
                "confidence": "LOW",
                "reason": f"Unknown data structure",
                "detection_path": "unknown_data_type"
            }

    def _process_c2c_data(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process only C2C data with C2C rules"""
        if self._resembles_c2c_attack(flow_data):
            print("[C2C] Traffic resembles C2C patterns, loading C2C model...")
            c2c_model = self._load_c2c_model()
            if c2c_model:
                c2c_features = self._extract_c2c_features(flow_data)
                result = c2c_model.predict(c2c_features)
                result["detection_path"] = "c2c_conditions_met"
                return result
            else:
                return self._c2c_rule_based_fallback(flow_data)
        else:
            return {
                "verdict": "BENIGN",
                "attack_type": "None",
                "confidence": "HIGH",
                "reason": "No C2C attack patterns detected",
                "detection_path": "c2c_conditions_not_met"
            }

    def _process_ddos_data(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process only DDoS data with DDoS rules"""
        if self._resembles_ddos_attack(flow_data):
            print("[DDoS] Traffic resembles DDoS patterns, loading DDoS model...")
            ddos_model = self._load_ddos_model()
            if ddos_model:
                ddos_features = self._extract_ddos_features(flow_data)
                result = ddos_model.predict(ddos_features)
                result["detection_path"] = "ddos_conditions_met"
                return result
            else:
                return self._ddos_rule_based_fallback(flow_data)
        else:
            return {
                "verdict": "BENIGN",
                "attack_type": "None",
                "confidence": "HIGH",
                "reason": "No DDoS attack patterns detected",
                "detection_path": "ddos_conditions_not_met"
            }

    def _process_mitm_data(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process only MITM data with MITM rules"""
        if self._resembles_mitm_attack(flow_data):
            print("[MITM] Traffic resembles MITM patterns, loading MITM model...")
            mitm_model = self._load_mitm_model()
            if mitm_model:
                mitm_features = self._extract_mitm_features(flow_data)
                result = mitm_model.predict(mitm_features)
                result["detection_path"] = "mitm_conditions_met"
                return result
            else:
                return self._mitm_rule_based_fallback(flow_data)
        else:
            return {
                "verdict": "BENIGN",
                "attack_type": "None",
                "confidence": "HIGH",
                "reason": "No MITM attack patterns detected",
                "detection_path": "mitm_conditions_not_met"
            }

    def _resembles_c2c_attack(self, flow_data: Dict[str, Any]) -> bool:
        """C2C rules (same as before)"""
        try:
            duration = flow_data.get('duration', 0)
            orig_bytes = flow_data.get('orig_bytes', 0)
            resp_bytes = flow_data.get('resp_bytes', 0)
            service = flow_data.get('service', 'unknown')
            conn_state = flow_data.get('conn_state', '')
            total_bytes = orig_bytes + resp_bytes

            # C2C Rule 1: Long duration with very low data (heartbeat)
            if duration > 60 and total_bytes < 500:
                print(f"[C2C-RULE] Long duration ({duration}s) with low data ({total_bytes} bytes)")
                return True

            # C2C Rule 2: Persistent unknown service
            if duration > 30 and service == 'unknown':
                print(f"[C2C-RULE] Long duration ({duration}s) with unknown service")
                return True

            # C2C Rule 3: Suspicious connection states
            if conn_state in ['S0', 'S1'] and duration > 10:
                print(f"[C2C-RULE] Suspicious connection state: {conn_state}")
                return True

            return False
        except Exception as e:
            print(f"[C2C-RULE-ERROR] {e}")
            return False

    def _resembles_ddos_attack(self, flow_data: Dict[str, Any]) -> bool:
        """DDoS rules - only processes DDoS data structure"""
        try:
            features = flow_data.get('features', {})
            packets_per_sec = features.get('Packets_Per_Sec', 0)
            bytes_per_sec = features.get('Bytes_Per_Sec', 0)
            unique_ips = features.get('Unique_IPs', 0)
            syn_ratio = features.get('SYN_Flag_Ratio', 0)
            udp_ratio = features.get('UDP_Ratio', 0)

            # DDoS Rule 1: Extremely high packet rate
            if packets_per_sec > 5000:
                print(f"[DDoS-RULE] High packet rate: {packets_per_sec} pps")
                return True

            # DDoS Rule 2: High bandwidth consumption
            if bytes_per_sec > 5000000:
                print(f"[DDoS-RULE] High bandwidth: {bytes_per_sec} B/s")
                return True

            # DDoS Rule 3: Many unique IPs (distributed attack)
            if unique_ips > 1000 and packets_per_sec > 100:
                print(f"[DDoS-RULE] Many unique IPs: {unique_ips}")
                return True

            # DDoS Rule 4: SYN flood characteristics
            if syn_ratio > 0.8 and packets_per_sec > 500:
                print(f"[DDoS-RULE] High SYN ratio: {syn_ratio}")
                return True

            return False
        except Exception as e:
            print(f"[DDoS-RULE-ERROR] {e}")
            return False

    def _resembles_mitm_attack(self, flow_data: Dict[str, Any]) -> bool:
        """MITM rules - only processes MITM data structure"""
        try:
            features_list = flow_data.get('features', [])
            if len(features_list) >= 8:
                mac_ip_inconsistency = features_list[0]
                packet_in_count = features_list[1]
                packet_rate = features_list[2]
                arp_request = features_list[5]
                arp_reply = features_list[6]

                # MITM Rule 1: High MAC-IP inconsistency
                if mac_ip_inconsistency > 0.2:
                    print(f"[MITM-RULE] High MAC-IP inconsistency: {mac_ip_inconsistency}")
                    return True

                # MITM Rule 2: Excessive ARP requests
                if arp_request > 50:
                    print(f"[MITM-RULE] Excessive ARP requests: {arp_request}")
                    return True

                # MITM Rule 3: High ARP packet rate
                if packet_rate > 20:
                    print(f"[MITM-RULE] High ARP packet rate: {packet_rate}")
                    return True

            return False
        except Exception as e:
            print(f"[MITM-RULE-ERROR] {e}")
            return False

    # Keep the existing extractor and fallback methods the same
    def _extract_c2c_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        return {key: flow_data.get(key, 0) for key in ['proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'history', 'orig_pkts', 'resp_pkts']}

    def _extract_ddos_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        return flow_data.get('features', {})

    def _extract_mitm_features(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        return {'ip_address': flow_data.get('ip_address', 'unknown'), 'features': flow_data.get('features', [])}

    def _c2c_rule_based_fallback(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        return {"verdict": "SUSPICIOUS", "attack_type": "C2C", "confidence": "MEDIUM", "reason": "C2C patterns detected but model unavailable"}

    def _ddos_rule_based_fallback(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        return {"verdict": "SUSPICIOUS", "attack_type": "DDoS", "confidence": "MEDIUM", "reason": "DDoS patterns detected but model unavailable"}

    def _mitm_rule_based_fallback(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        return {"verdict": "SUSPICIOUS", "attack_type": "MITM", "confidence": "MEDIUM", "reason": "MITM patterns detected but model unavailable"}