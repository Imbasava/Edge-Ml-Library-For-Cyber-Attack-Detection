# Filename: c2c.py
# Location: src/network_security_suite/models/
# PURPOSE: This script is for TRAINING the C2C detection model and
#          CONTAINS the prediction class for live inference.

import pandas as pd
import numpy as np
import joblib
import json
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

# Import the BaseModel to inherit from it
from .base_model import BaseModel

# ==========================================================================
# C2C PREDICTION CLASS
# ==========================================================================
class C2CModel(BaseModel):
    """
    The prediction implementation for the C2C model.
    """
    def __init__(self):
        # The model_name 'c2c' must match the directory name in 'trained_models/'
        super().__init__(model_name='c2c')
        
    def predict(self, features: dict) -> dict:
        """
        Makes a prediction for a C2C attack based on the input features.
        """
        # 1. Convert the single dictionary of features to a DataFrame
        input_df = pd.DataFrame([features], columns=self.raw_feature_names)
        
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
        
        # 4. Apply scaling and encoding
        numerical_scaled = self.scaler.transform(engineered_df[numerical_features])
        categorical_encoded = self.encoder.transform(engineered_df[categorical_features]).toarray()
        
        # 5. Combine preprocessed features into the final feature vector
        final_features = np.hstack([numerical_scaled, categorical_encoded])
        
        # 6. Make a prediction (predict_proba gives confidence scores)
        #    [0][1] gets the probability of the '1' class (malicious)
        probability = self.model.predict_proba(final_features)[0][1]
        
        # 7. Compare against the threshold from the metadata file
        threshold = self.metadata['threshold']
        is_attack = probability >= threshold
        
        # 8. Return a structured result
        result = {
            "model": "c2c",
            "verdict": "C2C Attack" if is_attack else "Benign",
            "confidence": f"{probability:.4f}",
            "threshold": threshold
        }
        return result

# ==========================================================================
# C2C TRAINING SECTION
# ==========================================================================

def engineer_features_df(df: pd.DataFrame) -> pd.DataFrame:
    """
    Applies the feature engineering logic across an entire DataFrame.
    This MUST match the logic used in the live prediction code (in BaseModel).
    """
    print("[Step 2.1] Engineering new features from raw data...")
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
    
    print("✓ Feature engineering complete.")
    return engineered_df

def train():
    """
    The main training function.
    """
    print("="*80)
    print("STARTING C2C MODEL TRAINING PIPELINE")
    print("="*80)
    
    # 1. SETUP PATHS AND PARAMETERS
    DATASET_PATH = 'path/to/your/c2c_training_data.csv' 
    OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'trained_models', 'c2c')
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    PREDICTION_THRESHOLD = 0.70

    # 2. LOAD DATA
    print(f"[Step 1] Loading dataset from '{DATASET_PATH}'...")
    try:
        print("[Warning] Using placeholder data. Replace with your actual dataset.")
        dummy_data = {
            'proto': ['tcp', 'udp', 'tcp', 'tcp', 'udp'], 
            'service': ['http', 'dns', '-', 'ssh', 'dns'],
            'duration': [1.5, 0.1, 2.99, 120.5, 0.2], 
            'orig_bytes': [500, 64, 0, 5000, 70],
            'resp_bytes': [1500, 128, 0, 8000, 130], 
            'conn_state': ['SF', 'SF', 'S0', 'SF', 'SF'],
            'history': ['ShADadFf', 'Dd', 'S', 'ShADadFf', 'Dd'], 
            'orig_pkts': [10, 2, 3, 150, 2], 
            'resp_pkts': [8, 2, 0, 145, 2],
            'label': [0, 0, 1, 1, 0]
        }
        df = pd.DataFrame(dummy_data)
        print(f"✓ Loaded {len(df)} records.")
    except FileNotFoundError:
        print(f"❌ ERROR: Dataset not found at '{DATASET_PATH}'. Please update the path.")
        return

    # Apply feature engineering
    df_engineered = engineer_features_df(df)
    
    # 3. PREPARE FOR TRAINING
    print("[Step 3] Preparing data for training...")
    numerical_features = [
        'duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts',
        'packet_rate', 'orig_bytes_per_pkt', 'resp_bytes_per_pkt',
        'pkt_ratio', 'byte_ratio', 'total_pkts', 'total_bytes',
        'has_response', 'bytes_per_sec'
    ]
    categorical_features = ['proto', 'service', 'conn_state', 'history']
    
    X = df_engineered[numerical_features + categorical_features]
    y = df_engineered['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    numeric_transformer = StandardScaler()
    categorical_transformer = OneHotEncoder(handle_unknown='ignore')
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, numerical_features),
            ('cat', categorical_transformer, categorical_features)
        ],
        remainder='passthrough'
    )

    # 4. TRAIN THE MODEL
    print("[Step 4] Training the RandomForestClassifier model...")
    model_pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))
    ])
    model_pipeline.fit(X_train, y_train)
    print("✓ Model training complete.")

    # 5. EVALUATE THE MODEL
    print("[Step 5] Evaluating model performance...")
    y_pred = model_pipeline.predict(X_test)
    print(f"\nModel Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

    # 6. SAVE THE ARTIFACTS
    print(f"[Step 6] Saving model artifacts to '{OUTPUT_DIR}'...")
    final_model = model_pipeline.named_steps['classifier']
    fitted_preprocessor = model_pipeline.named_steps['preprocessor']
    fitted_scaler = fitted_preprocessor.named_transformers_['num']
    fitted_encoder = fitted_preprocessor.named_transformers_['cat']
    
    joblib.dump(final_model, os.path.join(OUTPUT_DIR, 'c2c_detection_model.pkl'))
    joblib.dump(fitted_scaler, os.path.join(OUTPUT_DIR, 'c2c_scaler.pkl'))
    joblib.dump(fitted_encoder, os.path.join(OUTPUT_DIR, 'c2c_encoder.pkl'))
    
    metadata = {
        'description': 'C2C Attack Detection Model Artifacts',
        'threshold': PREDICTION_THRESHOLD,
        'numerical_features': numerical_features,
        'categorical_features': list(fitted_encoder.get_feature_names_out(categorical_features))
    }
    with open(os.path.join(OUTPUT_DIR, 'model_metadata.json'), 'w') as f:
        json.dump(metadata, f, indent=4)
        
    print("✓ All artifacts saved successfully.")
    print("\n" + "="*80)
    print("TRAINING PIPELINE FINISHED")
    print("="*80)

if __name__ == '__main__':
    # This allows you to run the training by executing the script directly:
    # python3 -m src.network_security_suite.models.c2c
    train()