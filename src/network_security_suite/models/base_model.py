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
    Abstract Base Class for all detection models (C2C, MITM, DDoS).
    Ensures that every model in the suite has a consistent interface
    for loading artifacts and making predictions.
    """
    def __init__(self, model_name: str, model_path: str = None):
        self.model_name = model_name
        
        # Allow explicit model path or use default structure
        if model_path:
            self.model_path = model_path
        else:
            # Go up one level from models/ to network_security_suite/, then into trained_models/
            base_dir = os.path.dirname(os.path.dirname(__file__))
            self.model_path = os.path.join(base_dir, 'trained_models', self.model_name)
        
        # These will be loaded by the load() method
        self.model = None
        self.scaler = None
        self.encoder = None
        self.metadata = None
        
        # Model-specific attributes (to be set by subclasses)
        self.raw_feature_names = []  # Expected raw features from C++ producer
        self.feature_type = ""       # c2c, mitm, ddos
        
        # Load model artifacts
        self.load()
    
    def _engineer_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Applies feature engineering logic. Can be overridden by subclasses.
        This MUST exactly match the logic used in the training script.
        """
        # Default implementation - subclasses can override if needed
        return df
    
    def load(self):
        """
        Loads the model artifacts from the specified directory.
        Generic loader that handles common artifacts.
        """
        print(f"[*] Loading model artifacts for '{self.model_name}' from '{self.model_path}'...")
        try:
            # Try to load common artifacts (subclasses can override)
            model_file = os.path.join(self.model_path, f'{self.model_name}_detection_model.pkl')
            scaler_file = os.path.join(self.model_path, f'{self.model_name}_scaler.pkl')
            encoder_file = os.path.join(self.model_path, f'{self.model_name}_encoder.pkl')
            metadata_file = os.path.join(self.model_path, 'model_metadata.json')
            
            if os.path.exists(model_file):
                self.model = joblib.load(model_file)
            if os.path.exists(scaler_file):
                self.scaler = joblib.load(scaler_file)
            if os.path.exists(encoder_file):
                self.encoder = joblib.load(encoder_file)
            if os.path.exists(metadata_file):
                with open(metadata_file, 'r') as f:
                    self.metadata = json.load(f)
            
            print(f"✓ Model '{self.model_name}' loaded successfully.")
            
        except FileNotFoundError as e:
            print(f"❌ ERROR: Could not load model artifacts for '{self.model_name}'. Make sure the files exist.")
            print(f"Details: {e}")
            raise
        except Exception as e:
            print(f"❌ ERROR: Unexpected error loading model '{self.model_name}': {e}")
            raise
    
    def is_loaded(self) -> bool:
        """Check if model artifacts are loaded successfully."""
        return self.model is not None
    
    @abstractmethod
    def predict(self, features: dict) -> dict:
        """
        The main prediction method that each subclass must implement.
        Args:
            features (dict): A dictionary of raw features from the C++ producer.
        Returns:
            dict: A dictionary containing the prediction result with standard format.
        """
        pass
    
    def get_prediction_template(self) -> dict:
        """
        Returns a standard template for prediction results.
        """
        return {
            "model": self.model_name,
            "feature_type": self.feature_type,
            "verdict": "UNKNOWN",
            "confidence": 0.0,
            "reason": "",
            "details": {}
        }





