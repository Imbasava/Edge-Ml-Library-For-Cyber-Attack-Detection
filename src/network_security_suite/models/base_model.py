# Filename: base_model.py
# Location: src/network_security_suite/models/
# PURPOSE: Defines the abstract base class for all detection models.

import pandas as pd
from abc import ABC, abstractmethod
import joblib
import json
import os

class BaseModel(ABC):
    """
    Abstract Base Class for detection models.
    Ensures that every model in the suite has a consistent interface
    for loading artifacts and making predictions.
    """
    def __init__(self, model_name: str):
        self.model_name = model_name
        # Go up one level from models/ to network_security_suite/, then into trained_models/
        base_dir = os.path.dirname(os.path.dirname(__file__))
        self.model_path = os.path.join(base_dir, 'trained_models', self.model_name)
        
        # These will be loaded by the load() method
        self.model = None
        self.scaler = None
        self.encoder = None
        self.metadata = None
        
        # These are the expected raw features from the C++ producer
        self.raw_feature_names = [
            'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 
            'conn_state', 'history', 'orig_pkts', 'resp_pkts'
        ]
        
        self.load()
    
    def _engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Applies the feature engineering logic.
        This MUST exactly match the logic used in the training script.
        """
        engineered_df = df.copy()
        duration = engineered_df['duration'].replace(0, 0.001)  # Avoid division by zero
        
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
    
    def load(self):
        """
        Loads the model artifacts from the specified directory.
        """
        print(f"[*] Loading model artifacts for '{self.model_name}' from '{self.model_path}'...")
        try:
            self.model = joblib.load(os.path.join(self.model_path, f'{self.model_name}_detection_model.pkl'))
            self.scaler = joblib.load(os.path.join(self.model_path, f'{self.model_name}_scaler.pkl'))
            self.encoder = joblib.load(os.path.join(self.model_path, f'{self.model_name}_encoder.pkl'))
            
            with open(os.path.join(self.model_path, 'model_metadata.json'), 'r') as f:
                self.metadata = json.load(f)
            
            print(f"✓ Model '{self.model_name}' loaded successfully.")
        except FileNotFoundError as e:
            print(f"❌ ERROR: Could not load model artifacts for '{self.model_name}'. Make sure the files exist.")
            print(f"Details: {e}")
            raise
    
    @abstractmethod
    def predict(self, features: dict) -> dict:
        """
        The main prediction method that each subclass must implement.
        Args:
            features (dict): A dictionary of raw features from the C++ producer.
        Returns:
            dict: A dictionary containing the prediction result.
        """
        pass