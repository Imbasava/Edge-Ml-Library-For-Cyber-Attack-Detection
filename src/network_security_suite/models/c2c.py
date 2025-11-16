# Filename: c2c.py
# Location: src/network_security_suite/models/
# PURPOSE: C2C detection model for live inference ONLY.

import pandas as pd
import numpy as np
import joblib
import json
import os

# Import the BaseModel to inherit from it
from .base_model import BaseModel

class C2CModel(BaseModel):
    """
    C2C Attack Detection Model for live inference.
    """
    def __init__(self, model_path: str = None):
        # Initialize with model name and optional custom path
        super().__init__(model_name='c2c', model_path=model_path)
        
        # Set model-specific attributes
        self.feature_type = "c2c"
        self.raw_feature_names = [
            'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 
            'conn_state', 'history', 'orig_pkts', 'resp_pkts'
        ]
        
    def predict(self, features: dict) -> dict:
        """
        Makes a prediction for a C2C attack based on the input features.
        """
        try:
            # Convert all values to Python native types first
            processed_features = {}
            for key, value in features.items():
                if hasattr(value, 'item'):  # numpy types
                    processed_features[key] = value.item() if hasattr(value, 'item') else float(value)
                else:
                    processed_features[key] = value
            
            # 1. Convert the single dictionary of features to a DataFrame
            input_df = pd.DataFrame([processed_features], columns=self.raw_feature_names)
            
            # 2. Apply the exact same feature engineering as in training
            engineered_df = self._engineer_features(input_df)

            # 3. Define features based on metadata
            numerical_features = self.metadata.get('numerical_features', [
                'duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts',
                'packet_rate', 'orig_bytes_per_pkt', 'resp_bytes_per_pkt',
                'pkt_ratio', 'byte_ratio', 'total_pkts', 'total_bytes',
                'has_response', 'bytes_per_sec'
            ])
            categorical_features = ['proto', 'service', 'conn_state', 'history']
            
            # 4. Apply scaling and encoding - convert to numpy array first
            numerical_data = engineered_df[numerical_features].values.astype(float)
            categorical_data = engineered_df[categorical_features].values
            
            numerical_scaled = self.scaler.transform(numerical_data)
            categorical_encoded = self.encoder.transform(categorical_data).toarray()
            
            # 5. Combine preprocessed features into the final feature vector
            final_features = np.hstack([numerical_scaled, categorical_encoded])
            
            # 6. Make a prediction
            probability = self.model.predict_proba(final_features)[0][1]
            
            # 7. Compare against the threshold
            threshold = self.metadata.get('threshold', 0.70)
            is_attack = probability >= threshold
            
            # 8. Return a structured result
            result = self.get_prediction_template()
            result.update({
                "verdict": "MALICIOUS" if is_attack else "BENIGN",
                "attack_type": "C2C" if is_attack else "None",
                "confidence": float(probability),
                "reason": f"ML model prediction (threshold: {threshold})",
                "details": {
                    "probability": float(probability),
                    "threshold": threshold,
                    "is_attack": is_attack
                }
            })
            return result
            
        except Exception as e:
            result = self.get_prediction_template()
            result.update({
                "verdict": "ERROR",
                "reason": f"Prediction failed: {str(e)}",
                "details": {"error": str(e), "features": features}
            })
            return result

    def _engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        C2C-specific feature engineering logic.
        This MUST exactly match the logic used during training.
        """
        engineered_df = df.copy()
        duration = engineered_df['duration'].replace(0, 0.001)
        
        engineered_df['packet_rate'] = (engineered_df['orig_pkts'] + engineered_df['resp_pkts']) / duration
        engineered_df['orig_bytes_per_pkt'] = (engineered_df['orig_bytes'] / engineered_df['orig_pkts']).fillna(0)
        engineered_df['resp_bytes_per_pkt'] = (engineered_df['resp_bytes'] / engineered_df['resp_pkts']).fillna(0)
        engineered_df['pkt_ratio'] = (engineered_df['orig_pkts'] / engineered_df['resp_pkts']).fillna(engineered_df['orig_pkts'])
        engineered_df['byte_ratio'] = (engineered_df['orig_bytes'] / engineered_df['resp_bytes']).fillna(engineered_df['orig_bytes'])
        engineered_df['total_pkts'] = engineered_df['orig_pkts'] + engineered_df['resp_pkts']
        engineered_df['total_bytes'] = engineered_df['orig_bytes'] + engineered_df['resp_bytes']
        engineered_df['has_response'] = (engineered_df['resp_pkts'] > 0).astype(int)
        engineered_df['bytes_per_sec'] = (engineered_df['total_bytes']) / duration
        
        return engineered_df