# Filename: ddos.py
# Location: src/network_security_suite/models/
# PURPOSE: DDoS detection model for live inference.

import numpy as np
import joblib
import json
import os
from .base_model import BaseModel

class DDoSModel(BaseModel):
    """
    DDoS Attack Detection Model for live inference.
    Uses ddos_model_joblib as the main model file.
    """
    def __init__(self, model_path: str = None):
        super().__init__(model_name='ddos', model_path=model_path)
        
        # Set model-specific attributes
        self.feature_type = "ddos"
        self.raw_feature_names = [
            'Packet_Size', 'Packets_Per_Sec', 'Flow_Duration', 'Bytes_Per_Sec',
            'Unique_IPs', 'Port_Diversity', 'TCP_Ratio', 'UDP_Ratio',
            'SYN_Flag_Ratio', 'ACK_Flag_Ratio'
        ]
        self.label_encoder = None
        
    def load(self):
        """
        Load DDoS model artifacts - uses ddos_model_joblib as main file
        """
        print(f"[*] Loading DDoS model artifacts from '{self.model_path}'...")
        try:
            # Try to load the bundled model file (ddos_model_joblib)
            bundled_model_file = os.path.join(self.model_path, 'ddos_model.joblib')
            if os.path.exists(bundled_model_file):
                # Load bundled model (contains model, scaler, label_encoder)
                model_data = joblib.load(bundled_model_file)
                self.model = model_data['model']
                self.scaler = model_data['scaler']
                self.label_encoder = model_data['label_encoder']
                print("✓ Loaded DDoS model from bundled file (ddos_model_joblib)")
            else:
                # If bundled file doesn't exist, try individual model files
                print("⚠ Bundled DDoS model not found, trying individual model files...")
                
                # Try Random Forest first (most common for DDoS)
                rf_model_file = os.path.join(self.model_path, 'ddos_model_random_forest.joblib')
                if os.path.exists(rf_model_file):
                    self.model = joblib.load(rf_model_file)
                    print("✓ Loaded DDoS Random Forest model")
                else:
                    # Try other model types as fallback
                    model_files = {
                        'svm': 'ddos_model_svm.joblib',
                        'logistic': 'ddos_model_logistic_regression.joblib'
                    }
                    
                    model_loaded = False
                    for model_type, filename in model_files.items():
                        model_file = os.path.join(self.model_path, filename)
                        if os.path.exists(model_file):
                            self.model = joblib.load(model_file)
                            print(f"✓ Loaded DDoS {model_type.upper()} model")
                            model_loaded = True
                            break
                    
                    if not model_loaded:
                        raise FileNotFoundError(f"No DDoS model file found in {self.model_path}")
                
                # Try to load scaler
                scaler_file = os.path.join(self.model_path, 'ddos_scaler.pkl')
                if os.path.exists(scaler_file):
                    self.scaler = joblib.load(scaler_file)
                else:
                    # Create a default scaler if none exists
                    from sklearn.preprocessing import StandardScaler
                    self.scaler = StandardScaler()
                    print("⚠ No scaler found, using default StandardScaler")
            
            # DDoS doesn't use categorical encoder
            self.encoder = None
            
            # Load metadata if available
            metadata_file = os.path.join(self.model_path, 'model_metadata.json')
            if os.path.exists(metadata_file):
                with open(metadata_file, 'r') as f:
                    self.metadata = json.load(f)
            else:
                # Default metadata for DDoS
                self.metadata = {
                    'threshold': 0.5,
                    'description': 'DDoS Attack Detection Model',
                    'model_type': 'Random Forest' if 'forest' in str(type(self.model)).lower() else str(type(self.model))
                }
            
            print(f"✓ DDoS model loaded successfully.")
            
        except Exception as e:
            print(f"❌ ERROR: Could not load DDoS model artifacts: {e}")
            raise

    def predict(self, features: dict) -> dict:
        """
        Makes a prediction for DDoS attack based on input features.
        Input format: features dict with DDoS feature names
        """
        try:
            # Create feature array in correct order
            feature_names = self.raw_feature_names
            X = np.array([[features.get(name, 0) for name in feature_names]])
            
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            # Predict
            pred = self.model.predict(X_scaled)
            proba = self.model.predict_proba(X_scaled)
            
            # Decode label if encoder available
            if self.label_encoder:
                label = self.label_encoder.inverse_transform(pred)[0]
            else:
                # Assume 0=Benign, 1=Attack if no encoder
                label = "BENIGN" if pred[0] == 0 else "ATTACK"
            
            confidence = max(proba[0])
            is_attack = label != "BENIGN"
            
            # Use threshold from metadata or default
            threshold = self.metadata.get('threshold', 0.5)
            is_attack_confident = confidence >= threshold
            
            # FIX: Convert all NumPy types to Python native types for JSON serialization
            confidence_python = float(confidence)
            threshold_python = float(threshold)
            label_python = str(label)
            is_attack_confident_python = bool(is_attack_confident)
            
            # Return structured result with Python native types
            result = self.get_prediction_template()
            result.update({
                "verdict": "MALICIOUS" if is_attack_confident_python else "BENIGN",
                "attack_type": "DDoS" if is_attack_confident_python else "None",
                "confidence": confidence_python,
                "reason": f"ML model prediction (label: {label_python})",
                "details": {
                    "probability": confidence_python,
                    "threshold": threshold_python,
                    "label": label_python,
                    "is_attack": is_attack_confident_python,
                    "packets_per_sec": float(features.get('Packets_Per_Sec', 0)),
                    "unique_ips": int(features.get('Unique_IPs', 0)),
                    "model_type": str(self.metadata.get('model_type', 'Unknown'))
                }
            })
            return result
            
        except Exception as e:
            result = self.get_prediction_template()
            result.update({
                "verdict": "ERROR",
                "reason": f"DDoS prediction failed: {str(e)}",
                "details": {"error": str(e)}
            })
            return result