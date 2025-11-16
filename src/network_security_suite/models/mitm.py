# Filename: mitm.py
# Location: src/network_security_suite/models/
# PURPOSE: MITM detection model for live inference.

import numpy as np
import joblib
import json
import os
from .base_model import BaseModel

class MITMModel(BaseModel):
    """
    MITM Attack Detection Model for live inference.
    Uses the same format as mitm_live.py
    """
    def __init__(self, model_path: str = None):
        super().__init__(model_name='mitm', model_path=model_path)
        
        # Set model-specific attributes
        self.feature_type = "mitm"
        self.raw_feature_names = [
            'mac_ip_inconsistency', 'packet_in_count', 'packet_rate', 'rtt_avg',
            'is_broadcast', 'arp_request', 'arp_reply', 'op_code_arp'
        ]
        
    def load(self):
        """
        Load MITM model artifacts - uses different file names than C2C
        """
        print(f"[*] Loading MITM model artifacts from '{self.model_path}'...")
        try:
            # MITM uses different file names
            model_file = os.path.join(self.model_path, 'semi_balanced_rf.pkl')
            scaler_file = os.path.join(self.model_path, 'semi_balanced_scaler.pkl')
            
            if os.path.exists(model_file):
                self.model = joblib.load(model_file)
            else:
                # Try alternative naming
                model_file = os.path.join(self.model_path, 'mitm_detection_model.pkl')
                if os.path.exists(model_file):
                    self.model = joblib.load(model_file)
                else:
                    raise FileNotFoundError(f"No model file found in {self.model_path}")
            
            if os.path.exists(scaler_file):
                self.scaler = joblib.load(scaler_file)
            else:
                # Try alternative naming
                scaler_file = os.path.join(self.model_path, 'mitm_scaler.pkl')
                if os.path.exists(scaler_file):
                    self.scaler = joblib.load(scaler_file)
                else:
                    raise FileNotFoundError(f"No scaler file found in {self.model_path}")
            
            # MITM doesn't use encoder, so we don't load it
            self.encoder = None
            
            # Load metadata if available
            metadata_file = os.path.join(self.model_path, 'model_metadata.json')
            if os.path.exists(metadata_file):
                with open(metadata_file, 'r') as f:
                    self.metadata = json.load(f)
            else:
                # Default metadata for MITM
                self.metadata = {
                    'threshold': 0.5,
                    'description': 'MITM Attack Detection Model'
                }
            
            print(f"✓ MITM model loaded successfully.")
            
        except Exception as e:
            print(f"❌ ERROR: Could not load MITM model artifacts: {e}")
            raise

    def predict(self, flow_data: dict) -> dict:
        """
        Makes a prediction for MITM attack based on input features.
        Input format: {"ip_address": "...", "features": [list of 8 features]}
        """
        try:
            ip_address = flow_data.get("ip_address", "unknown")
            features_list = flow_data.get("features", [])
            
            if len(features_list) != 8:
                raise ValueError(f"Expected 8 features, got {len(features_list)}")
            
            # Convert list to numpy array (same as mitm_live.py)
            sample = np.array([features_list])
            
            # Scale features
            scaled_sample = self.scaler.transform(sample)
            
            # Predict
            prediction = self.model.predict(scaled_sample)
            probabilities = self.model.predict_proba(scaled_sample)
            
            # Get confidence (same logic as mitm_live.py)
            if prediction[0] == 0:
                confidence = probabilities[0][0]  # Normal class probability
                is_attack = False
            else:
                confidence = probabilities[0][1]  # Attack class probability
                is_attack = True
            
            # Use threshold from metadata or default
            threshold = self.metadata.get('threshold', 0.5)
            is_attack_confident = confidence >= threshold
            
            # Return structured result
            result = self.get_prediction_template()
            result.update({
                "verdict": "MALICIOUS" if is_attack_confident else "BENIGN",
                "attack_type": "MITM" if is_attack_confident else "None",
                "confidence": float(confidence),
                "reason": f"ML model prediction (threshold: {threshold})",
                "ip_address": ip_address,
                "details": {
                    "probability": float(confidence),
                    "threshold": threshold,
                    "is_attack": is_attack_confident,
                    "raw_prediction": int(prediction[0])
                }
            })
            return result
            
        except Exception as e:
            result = self.get_prediction_template()
            result.update({
                "verdict": "ERROR",
                "reason": f"MITM prediction failed: {str(e)}",
                "details": {"error": str(e)}
            })
            return result