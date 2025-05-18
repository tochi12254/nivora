"""
Next-Generation Cyber Threat Anomaly Detection System
---------------------------------------------------------
This framework implements a sophisticated anomaly detection system
for real-time cyber threat detection with these components:

1. Data preprocessing pipeline
2. Feature engineering for cyber threat indicators
3. Multi-model ensemble approach combining:
   - Autoencoder for deep anomaly detection
   - Isolation Forest for traditional outlier detection
   - Temporal analysis for pattern detection
4. Visualization and explainability components
5. Model compression and export for production use
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler, OneHotEncoder, MinMaxScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_recall_curve, roc_curve, auc, confusion_matrix
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow.keras.models import Model, Sequential, load_model
from tensorflow.keras.layers import Input, Dense, Dropout, LSTM, TimeDistributed, RepeatVector
from tensorflow.keras.callbacks import EarlyStopping
import joblib
import json
import os
import time
from datetime import datetime
import onnx
import tf2onnx
import warnings
warnings.filterwarnings('ignore')

# Set random seeds for reproducibility
np.random.seed(42)
tf.random.set_seed(42)

class CyberThreatPreprocessor:
    """
    Handles preprocessing of cyber threat data from raw JSON format to ML-ready features
    """
    def __init__(self):
        self.categorical_cols = []
        self.numerical_cols = []
        self.timestamp_cols = ['network_details.timestamp']
        self.preprocessor = None
        self.feature_names = None
        
    def detect_column_types(self, df):
        """Automatically detect column types from dataframe"""
        self.numerical_cols = df.select_dtypes(include=['int64', 'float64']).columns.tolist()
        self.categorical_cols = df.select_dtypes(include=['object', 'category']).columns.tolist()
        # Remove timestamp columns from numerical/categorical
        for col in self.timestamp_cols:
            if col in self.numerical_cols:
                self.numerical_cols.remove(col)
            if col in self.categorical_cols:
                self.categorical_cols.remove(col)
                
        # Create separate lists for IPs and other categorical columns
        self.ip_cols = [col for col in self.categorical_cols if 'ip' in col.lower()]
        self.categorical_cols = [col for col in self.categorical_cols if col not in self.ip_cols]
        
        print(f"Detected {len(self.numerical_cols)} numerical columns")
        print(f"Detected {len(self.categorical_cols)} categorical columns")
        print(f"Detected {len(self.ip_cols)} IP address columns")
                
    def flatten_json(self, json_data):
        """Flatten nested JSON data into a flat dictionary with dot notation"""
        flat_data = {}
        
        def flatten(data, prefix=''):
            if isinstance(data, dict):
                for key, value in data.items():
                    if prefix:
                        new_key = f"{prefix}.{key}"
                    else:
                        new_key = key
                    flatten(value, new_key)
            elif isinstance(data, list):
                # For simplicity, we're only keeping the count of list items
                # More sophisticated approaches could be implemented
                flat_data[prefix + "_count"] = len(data)
                # For the first few items, we could extract them as individual features
                for i, item in enumerate(data[:3]):  # Extract first 3 items
                    flatten(item, f"{prefix}_{i}")
            else:
                flat_data[prefix] = data
                
        flatten(json_data)
        return flat_data
    
    def prepare_data(self, raw_data_list):
        """Convert a list of JSON data into a preprocessed pandas DataFrame"""
        # Flatten JSON data
        flattened_data = [self.flatten_json(json_data) for json_data in raw_data_list]
        
        # Create DataFrame
        df = pd.DataFrame(flattened_data)
        
        # Handle timestamp columns
        for col in self.timestamp_cols:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col])
                # Extract useful time features
                df[col + '_hour'] = df[col].dt.hour
                df[col + '_minute'] = df[col].dt.minute
                df[col + '_day_of_week'] = df[col].dt.dayofweek
                df[col + '_is_weekend'] = df[col].dt.dayofweek.isin([5, 6]).astype(int)
        
        # IP address feature engineering
        for ip_col in self.ip_cols:
            if ip_col in df.columns:
                # Extract features from IP addresses
                df[ip_col + '_is_private'] = df[ip_col].apply(self._is_private_ip).astype(int)
                df[ip_col + '_octet1'] = df[ip_col].apply(lambda x: self._get_octet(x, 0))
                df[ip_col + '_octet2'] = df[ip_col].apply(lambda x: self._get_octet(x, 1))
        
        # Fill missing values
        df = self._fill_missing_values(df)
        
        # Detect column types if not already set
        if not self.numerical_cols and not self.categorical_cols:
            self.detect_column_types(df)
            
        return df
    
    def _is_private_ip(self, ip):
        """Check if an IP address is private"""
        try:
            # Simple check for private IPs
            octets = ip.split('.')
            if len(octets) != 4:
                return False
            first_octet = int(octets[0])
            second_octet = int(octets[1])
            
            # Check for private IP ranges
            if first_octet == 10:  # 10.0.0.0/8
                return True
            elif first_octet == 172 and second_octet >= 16 and second_octet <= 31:  # 172.16.0.0/12
                return True
            elif first_octet == 192 and second_octet == 168:  # 192.168.0.0/16
                return True
            else:
                return False
        except:
            return False
    
    def _get_octet(self, ip, position):
        """Extract octet from IP address"""
        try:
            return int(ip.split('.')[position])
        except:
            return -1
    
    def _fill_missing_values(self, df):
        """Fill missing values appropriately based on column type"""
        # For numeric columns use median
        for col in df.select_dtypes(include=['int64', 'float64']).columns:
            df[col] = df[col].fillna(df[col].median() if not df[col].isna().all() else 0)
        
        # For categorical columns use mode or 'unknown'
        for col in df.select_dtypes(include=['object', 'category']).columns:
            mode_val = df[col].mode()[0] if not df[col].isna().all() else 'unknown'
            df[col] = df[col].fillna(mode_val)
            
        return df
    
    def build_preprocessor(self):
        """Build the scikit-learn preprocessing pipeline"""
        numerical_transformer = Pipeline(steps=[
            ('scaler', StandardScaler())
        ])
        
        categorical_transformer = Pipeline(steps=[
            ('onehot', OneHotEncoder(handle_unknown='ignore'))
        ])
        
        # Combine preprocessing steps
        self.preprocessor = ColumnTransformer(
            transformers=[
                ('num', numerical_transformer, self.numerical_cols),
                ('cat', categorical_transformer, self.categorical_cols)
            ],
            remainder='drop'  # Drop any columns not explicitly included
        )
        
        return self.preprocessor
    
    def fit_transform(self, df):
        """Fit preprocessor and transform data"""
        if self.preprocessor is None:
            self.build_preprocessor()
        
        transformed_data = self.preprocessor.fit_transform(df)
        
        # Store feature names for later use
        num_features = self.numerical_cols
        
        # Get one-hot encoded feature names
        cat_features = []
        if self.categorical_cols:
            encoder = self.preprocessor.named_transformers_['cat'].named_steps['onehot']
            cat_features = encoder.get_feature_names_out(self.categorical_cols).tolist()
        
        self.feature_names = num_features + cat_features
        
        return transformed_data
    
    def transform(self, df):
        """Transform data using fitted preprocessor"""
        if self.preprocessor is None:
            raise ValueError("Preprocessor not fitted. Call fit_transform first.")
        
        return self.preprocessor.transform(df)
    
    def save(self, filepath):
        """Save preprocessor to disk"""
        joblib.dump({
            'preprocessor': self.preprocessor,
            'numerical_cols': self.numerical_cols,
            'categorical_cols': self.categorical_cols,
            'timestamp_cols': self.timestamp_cols,
            'feature_names': self.feature_names
        }, filepath)
        
    def load(self, filepath):
        """Load preprocessor from disk"""
        saved_data = joblib.load(filepath)
        self.preprocessor = saved_data['preprocessor']
        self.numerical_cols = saved_data['numerical_cols']
        self.categorical_cols = saved_data['categorical_cols']
        self.timestamp_cols = saved_data['timestamp_cols']
        self.feature_names = saved_data['feature_names']

class TemporalFeatureExtractor:
    """
    Extracts temporal features for detecting time-based anomalies like:
    - Slow scanning behavior
    - Beaconing activities
    - Time-based attack patterns
    """
    def __init__(self, window_size=10, step_size=5):
        self.window_size = window_size
        self.step_size = step_size
    
    def create_sequences(self, data, time_column):
        """Create overlapping time windows from data"""
        sequences = []
        times = []
        
        # Sort data by time
        sorted_data = data.sort_values(by=time_column).reset_index(drop=True)
        
        for i in range(0, len(sorted_data) - self.window_size + 1, self.step_size):
            window_data = sorted_data.iloc[i:i+self.window_size]
            # Store sequence and its end time
            sequences.append(window_data.drop(columns=[time_column]).values)
            times.append(window_data[time_column].iloc[-1])
            
        return np.array(sequences), np.array(times)
    
    def extract_time_features(self, timestamps):
        """Extract features from timestamp differences"""
        # Convert to datetime if not already
        if not isinstance(timestamps[0], (datetime, np.datetime64, pd.Timestamp)):
            timestamps = pd.to_datetime(timestamps)
            
        # Calculate time differences in seconds
        time_diffs = [(timestamps[i] - timestamps[i-1]).total_seconds() 
                      for i in range(1, len(timestamps))]
        
        if not time_diffs:
            return np.zeros(5)  # Return zeros if not enough timestamps
            
        features = [
            np.mean(time_diffs),          # Average time between events
            np.std(time_diffs),           # Variability of timing
            np.min(time_diffs),           # Minimum time (fastest events)
            np.max(time_diffs),           # Maximum time (slowest events)
            np.percentile(time_diffs, 90) # 90th percentile
        ]
        
        return features

class CyberThreatDetector:
    """
    Multi-model ensemble for cyber threat anomaly detection 
    """
    def __init__(self, input_dim, sequence_length=None):
        self.input_dim = input_dim
        self.sequence_length = sequence_length
        self.models = {}
        self.threshold = None
        self.ensemble_weights = {
            'autoencoder': 0.4,
            'isolation_forest': 0.3,
            'lstm_autoencoder': 0.3
        }
    
    def build_autoencoder(self, encoding_dim=16):
        """Build autoencoder model for point anomaly detection"""
        input_layer = Input(shape=(self.input_dim,))
        
        # Encoder layers
        encoded = Dense(64, activation='relu')(input_layer)
        encoded = Dropout(0.2)(encoded)
        encoded = Dense(32, activation='relu')(encoded)
        encoded = Dense(encoding_dim, activation='relu')(encoded)
        
        # Decoder layers
        decoded = Dense(32, activation='relu')(encoded)
        decoded = Dropout(0.2)(decoded)
        decoded = Dense(64, activation='relu')(decoded)
        decoded = Dense(self.input_dim, activation='sigmoid')(decoded)
        
        # Autoencoder model
        autoencoder = Model(input_layer, decoded)
        autoencoder.compile(optimizer='adam', loss='mean_squared_error')
        
        # Also create an encoder model for feature extraction
        encoder = Model(input_layer, encoded)
        
        self.models['autoencoder'] = autoencoder
        self.models['encoder'] = encoder
        
        return autoencoder
    
    def build_isolation_forest(self, contamination=0.01):
        """Build Isolation Forest model for traditional outlier detection"""
        model = IsolationForest(
            n_estimators=200,
            max_samples='auto',
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        self.models['isolation_forest'] = model
        return model
    
    def build_lstm_autoencoder(self, encoding_dim=16):
        """Build LSTM-based autoencoder for sequence anomaly detection"""
        if self.sequence_length is None:
            raise ValueError("sequence_length must be specified for LSTM autoencoder")
            
        # Define input shape: (sequence_length, features)
        input_shape = (self.sequence_length, self.input_dim)
        
        # Build the model
        model = Sequential([
            # Encoder
            LSTM(64, activation='relu', return_sequences=True, 
                 input_shape=input_shape),
            LSTM(32, activation='relu', return_sequences=False),
            
            # Representation
            Dense(encoding_dim, activation='relu'),
            
            # Decoder (reconstruct the sequence)
            RepeatVector(self.sequence_length),
            LSTM(32, activation='relu', return_sequences=True),
            LSTM(64, activation='relu', return_sequences=True),
            TimeDistributed(Dense(self.input_dim))
        ])
        
        model.compile(optimizer='adam', loss='mae')
        self.models['lstm_autoencoder'] = model
        
        return model
    
    def fit_autoencoder(self, X_train, X_val=None, epochs=50, batch_size=32):
        """Fit the autoencoder model"""
        callbacks = [EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)]
        
        if X_val is not None:
            history = self.models['autoencoder'].fit(
                X_train, X_train,
                epochs=epochs,
                batch_size=batch_size,
                shuffle=True,
                validation_data=(X_val, X_val),
                callbacks=callbacks,
                verbose=1
            )
        else:
            # Use a portion of training data as validation
            history = self.models['autoencoder'].fit(
                X_train, X_train,
                epochs=epochs,
                batch_size=batch_size,
                shuffle=True,
                validation_split=0.2,
                callbacks=callbacks,
                verbose=1
            )
        return history
    
    def fit_isolation_forest(self, X_train):
        """Fit the isolation forest model"""
        self.models['isolation_forest'].fit(X_train)
        return self.models['isolation_forest']
    
    def fit_lstm_autoencoder(self, X_train_seq, X_val_seq=None, epochs=50, batch_size=32):
        """Fit the LSTM autoencoder model"""
        callbacks = [EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)]
        
        if X_val_seq is not None:
            history = self.models['lstm_autoencoder'].fit(
                X_train_seq, X_train_seq,
                epochs=epochs,
                batch_size=batch_size,
                shuffle=True,
                validation_data=(X_val_seq, X_val_seq),
                callbacks=callbacks,
                verbose=1
            )
        else:
            # Use a portion of training data as validation
            history = self.models['lstm_autoencoder'].fit(
                X_train_seq, X_train_seq,
                epochs=epochs,
                batch_size=batch_size,
                shuffle=True,
                validation_split=0.2,
                callbacks=callbacks,
                verbose=1
            )
        return history
    
    def find_threshold(self, X_train, X_train_seq=None, contamination=0.01):
        """Determine anomaly thresholds based on training data"""
        thresholds = {}
        
        # Calculate reconstruction error for point data
        if 'autoencoder' in self.models:
            preds = self.models['autoencoder'].predict(X_train)
            mse = np.mean(np.power(X_train - preds, 2), axis=1)
            # Set threshold at the percentile corresponding to contamination
            thresholds['autoencoder'] = np.percentile(mse, 100 * (1 - contamination))
        
        # Decision scores for isolation forest are already calibrated
        if 'isolation_forest' in self.models:
            # Isolation Forest scores: negative = anomaly, positive = normal
            # We'll convert to same direction as other models (higher = more anomalous)
            scores = -self.models['isolation_forest'].decision_function(X_train)
            thresholds['isolation_forest'] = np.percentile(scores, 100 * (1 - contamination))
        
        # Calculate reconstruction error for sequence data
        if 'lstm_autoencoder' in self.models and X_train_seq is not None:
            preds_seq = self.models['lstm_autoencoder'].predict(X_train_seq)
            # Mean absolute error per sequence
            mae = np.mean(np.abs(X_train_seq - preds_seq), axis=(1, 2))
            thresholds['lstm_autoencoder'] = np.percentile(mae, 100 * (1 - contamination))
        
        self.thresholds = thresholds
        return thresholds
    
    def predict_anomaly_scores(self, X, X_seq=None):
        """Calculate anomaly scores from all models"""
        scores = {}
        
        # Autoencoder reconstruction error
        if 'autoencoder' in self.models:
            preds = self.models['autoencoder'].predict(X)
            scores['autoencoder'] = np.mean(np.power(X - preds, 2), axis=1)
        
        # Isolation Forest decision scores (convert to higher = more anomalous)
        if 'isolation_forest' in self.models:
            scores['isolation_forest'] = -self.models['isolation_forest'].decision_function(X)
        
        # LSTM Autoencoder reconstruction error for sequences
        if 'lstm_autoencoder' in self.models and X_seq is not None:
            preds_seq = self.models['lstm_autoencoder'].predict(X_seq)
            scores['lstm_autoencoder'] = np.mean(np.abs(X_seq - preds_seq), axis=(1, 2))
        
        return scores
    
    def predict(self, X, X_seq=None):
        """Predict anomalies (1 for anomaly, 0 for normal)"""
        scores = self.predict_anomaly_scores(X, X_seq)
        
        # Initialize predictions
        all_predictions = np.zeros(X.shape[0])
        
        # For each model, mark anomalies if score exceeds threshold
        if 'autoencoder' in scores and 'autoencoder' in self.thresholds:
            all_predictions += (scores['autoencoder'] > self.thresholds['autoencoder']) * self.ensemble_weights['autoencoder']
            
        if 'isolation_forest' in scores and 'isolation_forest' in self.thresholds:
            all_predictions += (scores['isolation_forest'] > self.thresholds['isolation_forest']) * self.ensemble_weights['isolation_forest']
        
        # For sequence model, we need to map sequence predictions back to individual points
        # This is a simplification; in production you'd need a more robust method
        if 'lstm_autoencoder' in scores and 'lstm_autoencoder' in self.thresholds:
            seq_predictions = (scores['lstm_autoencoder'] > self.thresholds['lstm_autoencoder']) * self.ensemble_weights['lstm_autoencoder']
            # Simple approach: mark all points in anomalous sequences
            # In production, you'd want a more sophisticated approach
            all_predictions += seq_predictions[0] if len(seq_predictions) > 0 else 0
            
        # Final decision: something is an anomaly if the weighted sum exceeds 0.5
        return (all_predictions > 0.5).astype(int)
    
    def get_anomaly_explanation(self, X, X_original, feature_names, anomaly_indices, top_n=5):
        """
        Generate explanations for why specific points were flagged as anomalies
        based on feature contributions to reconstruction error
        """
        explanations = []
        
        # Get autoencoder predictions for the anomalies
        preds = self.models['autoencoder'].predict(X[anomaly_indices])
        
        # For each anomaly
        for i, idx in enumerate(anomaly_indices):
            # Calculate feature-wise squared error
            feature_errors = np.power(X[idx] - preds[i], 2)
            
            # Get the top contributing features
            top_feature_indices = np.argsort(feature_errors)[-top_n:][::-1]
            
            explanation = {
                'index': idx,
                'total_error': np.sum(feature_errors),
                'top_features': []
            }
            
            # Add detailed information about top features
            for feat_idx in top_feature_indices:
                if feat_idx < len(feature_names):
                    feat_name = feature_names[feat_idx]
                    # Get original value if possible
                    orig_value = X_original.iloc[idx][feat_name] if feat_name in X_original.columns else "Unknown"
                    
                    explanation['top_features'].append({
                        'feature': feat_name,
                        'contribution': float(feature_errors[feat_idx]),
                        'original_value': orig_value,
                        'expected_value': float(preds[i][feat_idx])
                    })
            
            explanations.append(explanation)
            
        return explanations
    
    def save_models(self, base_path):
        """Save all models to disk"""
        # Create directory if it doesn't exist
        os.makedirs(base_path, exist_ok=True)
        
        # Save deep learning models
        if 'autoencoder' in self.models:
            self.models['autoencoder'].save(os.path.join(base_path, 'autoencoder.h5'))
            self.models['encoder'].save(os.path.join(base_path, 'encoder.h5'))
            
        if 'lstm_autoencoder' in self.models:
            self.models['lstm_autoencoder'].save(os.path.join(base_path, 'lstm_autoencoder.h5'))
        
        # Save sklearn models
        if 'isolation_forest' in self.models:
            joblib.dump(self.models['isolation_forest'], 
                        os.path.join(base_path, 'isolation_forest.joblib'))
        
        # Save thresholds and configuration
        joblib.dump({
            'thresholds': self.thresholds,
            'ensemble_weights': self.ensemble_weights,
            'input_dim': self.input_dim,
            'sequence_length': self.sequence_length
        }, os.path.join(base_path, 'config.joblib'))
    
    def load_models(self, base_path):
        """Load all models from disk"""
        # Load deep learning models
        if os.path.exists(os.path.join(base_path, 'autoencoder.h5')):
            self.models['autoencoder'] = load_model(os.path.join(base_path, 'autoencoder.h5'))
            
        if os.path.exists(os.path.join(base_path, 'encoder.h5')):
            self.models['encoder'] = load_model(os.path.join(base_path, 'encoder.h5'))
            
        if os.path.exists(os.path.join(base_path, 'lstm_autoencoder.h5')):
            self.models['lstm_autoencoder'] = load_model(os.path.join(base_path, 'lstm_autoencoder.h5'))
        
        # Load sklearn models
        if os.path.exists(os.path.join(base_path, 'isolation_forest.joblib')):
            self.models['isolation_forest'] = joblib.load(
                os.path.join(base_path, 'isolation_forest.joblib'))
        
        # Load configuration
        if os.path.exists(os.path.join(base_path, 'config.joblib')):
            config = joblib.load(os.path.join(base_path, 'config.joblib'))
            self.thresholds = config['thresholds']
            self.ensemble_weights = config['ensemble_weights']
            self.input_dim = config['input_dim']
            self.sequence_length = config['sequence_length']
    
    def convert_to_onnx(self, base_path):
        """Convert models to ONNX format for faster inference"""
        os.makedirs(os.path.join(base_path, 'onnx'), exist_ok=True)
        
        # Convert Keras models to ONNX
        if 'autoencoder' in self.models:
            # Create ONNX model
            input_signature = [tf.TensorSpec([None, self.input_dim], tf.float32, name='input')]
            onnx_model, _ = tf2onnx.convert.from_keras(self.models['autoencoder'], input_signature)
            
            # Save ONNX model
            onnx_path = os.path.join(base_path, 'onnx', 'autoencoder.onnx')
            onnx.save_model(onnx_model, onnx_path)
            print(f"Saved autoencoder ONNX model at {onnx_path}")
        
        if 'lstm_autoencoder' in self.models and self.sequence_length is not None:
            # Create ONNX model
            input_signature = [tf.TensorSpec([None, self.sequence_length, self.input_dim], tf.float32, name='input')]
            onnx_model, _ = tf2onnx.convert.from_keras(self.models['lstm_autoencoder'], input_signature)
            
            # Save ONNX model
            onnx_path = os.path.join(base_path, 'onnx', 'lstm_autoencoder.onnx')
            onnx.save_model(onnx_model, onnx_path)
            print(f"Saved LSTM autoencoder ONNX model at {onnx_path}")

class CyberThreatVisualization:
    """
    Visualization tools for cyber threat anomalies
    """
    def __init__(self):
        self.style_setup()
    
    def style_setup(self):
        """Set up plotting style"""
        plt.style.use('seaborn-v0_8-darkgrid')
        plt.rcParams['figure.figsize'] = (12, 8)
        plt.rcParams['font.size'] = 12
    
    def plot_anomaly_scores(self, scores, thresholds, title="Anomaly Scores Distribution"):
        """Plot distribution of anomaly scores with threshold markers"""
        fig, axes = plt.subplots(len(scores), 1, figsize=(12, 4*len(scores)))
        
        # Handle single score case
        if len(scores) == 1:
            axes = [axes]
            
        for i, (model_name, score) in enumerate(scores.items()):
            sns.histplot(score, kde=True, ax=axes[i])
            
            if model_name in thresholds:
                axes[i].axvline(thresholds[model_name], color='red', linestyle='--', 
                              label=f'Threshold: {thresholds[model_name]:.4f}')
                
            axes[i].set_title(f"{model_name.replace('_', ' ').title()} Scores")
            axes[i].set_xlabel("Anomaly Score")
            axes[i].set_ylabel("Count")
            axes[i].legend()
            
        plt.tight_layout()
        return fig
    
    def plot_precision_recall_curve(self, y_true, scores, title="Precision-Recall Curve"):
        """Plot precision-recall curves for each model"""
        fig, ax = plt.subplots(figsize=(10, 8))
        
        for model_name, score in scores.items():
            precision, recall, _ = precision_recall_curve(y_true, score)
            pr_auc = auc(recall, precision)
            
            ax.plot(recall, precision, lw=2, 
                   label=f'{model_name} (AUC = {pr_auc:.3f})')
            
        ax.set_xlabel('Recall')
        ax.set_ylabel('Precision')
        ax.set_title(title)
        ax.legend(loc='best')
        ax.grid(True)
        
        return fig
    
    def plot_roc_curve(self, y_true, scores, title="ROC Curve"):
        """Plot ROC curves for each model"""
        fig, ax = plt.subplots(figsize=(10, 8))
        
        for model_name, score in scores.items():
            fpr, tpr, _ = roc_curve(y_true, score)
            roc_auc = auc(fpr, tpr)
            
            ax.plot(fpr, tpr, lw=2, 
                   label=f'{model_name} (AUC = {roc_auc:.3f})')
            
        # Plot diagonal line for random classifier
        ax.plot([0, 1], [0, 1], color='gray', lw=1, linestyle='--', 
               label='Random (AUC = 0.500)')
        
        ax.set_xlabel('False Positive Rate')
        ax.set_ylabel('True Positive Rate')
        ax.set_title(title)
        ax.legend(loc='best')
        ax.grid(True)
        
        return fig
    
    def plot_confusion_matrix(self, y_true, y_pred, title="Confusion Matrix"):
        """Plot confusion matrix"""
        cm = confusion_matrix(y_true, y_pred)
        
        fig, ax = plt.subplots(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax)
        
        ax.set_xlabel('Predicted Labels')
        ax.set_ylabel('True Labels')
        ax.set_title(title)
        ax.set_xticklabels(['Normal', 'Anomaly'])
        ax.set_yticklabels(['Normal', 'Anomaly'])
        
        return fig
    
    def plot_feature_importance(self, feature_names, importances, title="Feature Importance", top_n=20):
        """Plot feature importance"""
        # Get the top N features
        indices = np.argsort(importances)[-top_n:]
        top_features = [feature_names[i] for i in indices]
        top_importances = importances[indices]
        
        fig, ax = plt.subplots(figsize=(10, 8))
        sns.barplot(x=top_importances, y=top_features, ax=ax)
        
        ax.set_title(title)
        ax.set_xlabel('Importance')
        ax.set_ylabel('Feature')
        
        return fig
    
    def plot_anomaly_timeline(self, timestamps, anomaly_scores, threshold, title="Anomaly Timeline"):
        """Plot anomalies over time"""
        fig, ax = plt.subplots(figsize=(14, 6))
        
        # Plot all scores
        ax.plot(timestamps, anomaly_scores, 'b-', alpha=0.5, label='Anomaly Score')
        
        # Mark anomalies
        anomalies = anomaly_scores > threshold
        ax.scatter(timestamps[anomalies], anomaly_scores[anomalies], 
                  color='red', label='Detected Anomalies')
        
        # Plot threshold
        ax.axhline(y=threshold, color='r', linestyle='--', label=f'Threshold: {threshold:.4f}')
        
        ax.set_title(title)
        ax.set_xlabel('Time')
        ax.set_ylabel('Anomaly Score')
        ax.legend()
        ax.grid(True)
        
        # Format x-axis with dates
        fig.autofmt_xdate()
        
        return fig
    
    def plot_latent_space(self, encoder, X, y=None, title="Latent Space Visualization"):
        """
        Visualize the latent space from the encoder
        Uses PCA if latent dimension > 2
        """
        # Get encoded features
        encoded_features = encoder.predict(X)
        
        # Use PCA for dimensionality reduction if needed
        if encoded_features.shape[1] > 2:
            from sklearn.decomposition import PCA
            pca = PCA(n_components=2)
            encoded_features = pca.fit_transform(encoded_features)
            dim_method = "PCA"
        else:
            dim_method = "Original"
        
        fig, ax = plt.subplots(figsize=(10, 8))
        
        # Color by labels if provided
        if y is not None:
            scatter = ax.scatter(encoded_features[:, 0], encoded_features[:, 1], 
                                c=y, cmap='viridis', alpha=0.8)
            legend = ax.legend(*scatter.legend_elements(),
                              title="Classes")
            ax.add_artist(legend)
        else:
            ax.scatter(encoded_features[:, 0], encoded_features[:, 1], alpha=0.8)
        
        ax.set_title(f"{title} ({dim_method})")
        ax.set_xlabel("Dimension 1")
        ax.set_ylabel("Dimension 2")
        ax.grid(True)
        
        return fig

class ModelCompression:
    """
    Methods for compressing models for use in lightweight environments
    """
    def __init__(self):
        pass
    
    def quantize_tensorflow_model(self, model, output_path):
        """Quantize TensorFlow model to reduce size (int8 quantization)"""
        # Convert to TFLite
        converter = tf.lite.TFLiteConverter.from_keras_model(model)
        
        # Apply quantization
        converter.optimizations = [tf.lite.Optimize.DEFAULT]
        converter.target_spec.supported_types = [tf.int8]
        
        # Representative dataset generator function
        def representative_dataset_gen():
            # Generate dummy data matching input shape
            input_shape = model.input_shape
            batch_size = 1
            input_dim = input_shape[1] if len(input_shape) == 2 else input_shape[1] * input_shape[2]
            for _ in range(100):  # 100 samples
                dummy_input = np.random.random((batch_size,) + input_shape[1:]).astype(np.float32)
                yield [dummy_input]
        
        converter.representative_dataset = representative_dataset_gen
        
        # Convert to TFLite model
        tflite_model = converter.convert()
        
        # Save model
        with open(output_path, 'wb') as f:
            f.write(tflite_model)
            
        return output_path
    
    def compress_sklearn_model(self, model, output_path):
        """Compress sklearn model using joblib compression"""
        # Compress with highest compression level
        joblib.dump(model, output_path, compress=9)
        return output_path
    
    def convert_to_tfjs(self, model, output_dir):
        """Convert Keras model to TensorFlow.js format for web usage"""
        # Check if tfjs module is available, if not suggest installation
        try:
            import tensorflowjs as tfjs
        except ImportError:
            print("TensorFlow.js not installed. Install with: pip install tensorflowjs")
            return None
            
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Convert model
        tfjs.converters.save_keras_model(model, output_dir)
        
        return output_dir

class CyberThreatTrainer:
    """
    Training pipeline for cyber threat anomaly detection
    """
    def __init__(self):
        self.preprocessor = CyberThreatPreprocessor()
        self.temporal_extractor = TemporalFeatureExtractor()
        self.detector = None
        self.visualizer = CyberThreatVisualization()
        self.compressor = ModelCompression()
        
    def prepare_data(self, raw_data_list, labels=None):
        """Process raw data into ML-ready format"""
        # Prepare data using preprocessor
        df = self.preprocessor.prepare_data(raw_data_list)
        
        # Add labels if provided
        if labels is not None:
            df['label'] = labels
            
        # Handle timestamp column for temporal analysis
        timestamp_col = None
        if self.preprocessor.timestamp_cols and self.preprocessor.timestamp_cols[0] in df.columns:
            timestamp_col = self.preprocessor.timestamp_cols[0]
            
        # Create feature matrix
        feature_cols = df.columns.drop(['label'] if labels is not None else [])
        if timestamp_col:
            feature_cols = feature_cols.drop(timestamp_col)
            
        X = df[feature_cols]
        y = df['label'] if labels is not None else None
        
        # Transform features
        X_transformed = self.preprocessor.fit_transform(X)
        
        # Create sequences for temporal analysis if timestamp available
        X_sequences = None
        if timestamp_col:
            X_sequences, seq_times = self.temporal_extractor.create_sequences(df, timestamp_col)
            
        return X, X_transformed, X_sequences, y, df
    
    def generate_synthetic_attacks(self, normal_data, num_attacks=100, attack_types=None):
        """Generate synthetic attack patterns for training"""
        if attack_types is None:
            attack_types = ['data_exfiltration', 'scanning', 'injection', 'unusual_protocol']
            
        synthetic_attacks = []
        
        # Sample base data from normal
        base_indices = np.random.choice(len(normal_data), num_attacks)
        
        for idx in base_indices:
            base_record = dict(normal_data.iloc[idx])
            attack_type = np.random.choice(attack_types)
            
            # Modify the base record based on attack type
            if attack_type == 'data_exfiltration':
                # Simulate data exfiltration with larger packet sizes and unusual destination
                if 'content_analysis.packet_size' in base_record:
                    base_record['content_analysis.packet_size'] *= np.random.uniform(5, 10)
                if 'destination_ip' in base_record:
                    # Create suspicious IP
                    base_record['destination_ip'] = f"{np.random.randint(200, 220)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
                
            elif attack_type == 'scanning':
                # Simulate port scanning with many small packets
                if 'content_analysis.packet_size' in base_record:
                    base_record['content_analysis.packet_size'] = np.random.uniform(20, 100)
                if 'network_details.protocol' in base_record:
                    base_record['network_details.protocol'] = np.random.choice(['TCP', 'UDP'])
                
            elif attack_type == 'injection':
                # Simulate injection attacks
                if 'security_headers_status' in base_record:
                    base_record['security_headers_status'] = 'missing'
                if 'content_analysis.content_type' in base_record:
                    base_record['content_analysis.content_type'] = np.random.choice(['text/html', 'application/x-www-form-urlencoded'])
                
            elif attack_type == 'unusual_protocol':
                # Simulate unusual protocol behavior
                if 'network_details.protocol' in base_record:
                    base_record['network_details.protocol'] = np.random.choice(['ICMP', 'GRE', 'ESP'])
                if 'threat_score' in base_record:
                    base_record['threat_score'] = np.random.uniform(60, 95)
            
            # Mark as an attack
            base_record['is_attack'] = 1
            synthetic_attacks.append(base_record)
            
        # Convert to DataFrame
        attack_df = pd.DataFrame(synthetic_attacks)
        
        return attack_df
    
    def train(self, raw_data_list, labels=None, contamination=0.01, synthetic_attacks=True):
        """Train the complete anomaly detection pipeline"""
        print("Step 1: Preparing data...")
        X, X_transformed, X_sequences, y, df = self.prepare_data(raw_data_list, labels)
        
        # Generate synthetic attacks if requested and no labels provided
        if synthetic_attacks and labels is None:
            print("Step 2: Generating synthetic attacks...")
            attack_df = self.generate_synthetic_attacks(df, num_attacks=int(len(df) * 0.05))
            
            # Combine normal data with synthetic attacks
            combined_df = pd.concat([df.assign(is_attack=0), attack_df])
            
            # Re-prepare data with synthetic attacks
            X, X_transformed, X_sequences, y, df = self.prepare_data(
                [combined_df.iloc[i].to_dict() for i in range(len(combined_df))], 
                combined_df['is_attack'].values
            )
        
        # Initialize detector
        input_dim = X_transformed.shape[1]
        sequence_length = X_sequences.shape[1] if X_sequences is not None else None
        
        print(f"Step 3: Building models with input_dim={input_dim}, sequence_length={sequence_length}...")
        self.detector = CyberThreatDetector(input_dim, sequence_length)
        
        # Split data if we have labels
        if y is not None:
            X_train, X_test, y_train, y_test = train_test_split(
                X_transformed, y, test_size=0.2, random_state=42, stratify=y
            )
            
            if X_sequences is not None:
                # Simple approach - in production you'd need more careful sequence splitting
                train_indices = np.random.choice(len(X_sequences), int(len(X_sequences) * 0.8), replace=False)
                test_indices = np.array(list(set(range(len(X_sequences))) - set(train_indices)))
                
                X_seq_train = X_sequences[train_indices]
                X_seq_test = X_sequences[test_indices]
            else:
                X_seq_train = X_seq_test = None
        else:
            # Without labels, use all data for training
            X_train = X_transformed
            X_test = X_transformed
            y_test = None
            X_seq_train = X_sequences
            X_seq_test = X_sequences
        
        # Train autoencoder
        print("Step 4: Training autoencoder...")
        self.detector.build_autoencoder()
        history_ae = self.detector.fit_autoencoder(X_train, X_test, epochs=20)
        
        # Train isolation forest
        print("Step 5: Training isolation forest...")
        self.detector.build_isolation_forest(contamination=contamination)
        self.detector.fit_isolation_forest(X_train)
        
        # Train LSTM autoencoder if we have sequential data
        if X_seq_train is not None:
            print("Step 6: Training LSTM autoencoder...")
            self.detector.build_lstm_autoencoder()
            history_lstm = self.detector.fit_lstm_autoencoder(X_seq_train, X_seq_test, epochs=20)
        
        # Find thresholds
        print("Step 7: Finding optimal thresholds...")
        thresholds = self.detector.find_threshold(X_train, X_seq_train, contamination=contamination)
        
        # Evaluate if we have labels
        if y is not None:
            print("Step 8: Evaluating models...")
            # Get anomaly scores
            scores = self.detector.predict_anomaly_scores(X_test, X_seq_test)
            
            # Make predictions
            y_pred = self.detector.predict(X_test, X_seq_test)
            
            # Calculate metrics
            from sklearn.metrics import classification_report, precision_score, recall_score, f1_score
            
            print("\nClassification Report:")
            print(classification_report(y_test, y_pred))
            
            print("\nKey Metrics:")
            print(f"Precision: {precision_score(y_test, y_pred):.4f}")
            print(f"Recall: {recall_score(y_test, y_pred):.4f}")
            print(f"F1 Score: {f1_score(y_test, y_pred):.4f}")
            
            # Plot evaluation curves
            print("\nGenerating visualizations...")
            self.visualizer.plot_precision_recall_curve(y_test, scores)
            self.visualizer.plot_roc_curve(y_test, scores)
            self.visualizer.plot_confusion_matrix(y_test, y_pred)
            
        # Save preprocessor and models
        print("Step 9: Saving models...")
        os.makedirs("models", exist_ok=True)
        self.preprocessor.save("models/preprocessor.joblib")
        self.detector.save_models("models")
        
        print("Step 10: Compressing models for production...")
        self.detector.convert_to_onnx("models")
        
        if "autoencoder" in self.detector.models:
            self.compressor.quantize_tensorflow_model(
                self.detector.models["autoencoder"], 
                "models/autoencoder_quantized.tflite"
            )
        
        print("Training completed successfully!")
        return self.detector, self.preprocessor

class CyberThreatInferenceEngine:
    """
    Real-time inference engine for production deployment
    """
    def __init__(self, model_path="models"):
        self.preprocessor = CyberThreatPreprocessor()
        self.detector = CyberThreatDetector(input_dim=None)  # Will be loaded from saved models
        
        # Load models
        self.load_models(model_path)
        
        # Configure internal state for temporal analysis
        self.recent_observations = []
        self.window_size = 10
        self.sequence_length = self.detector.sequence_length
        
    def load_models(self, model_path):
        """Load preprocessor and detector models"""
        try:
            # Load preprocessor
            self.preprocessor.load(os.path.join(model_path, "preprocessor.joblib"))
            
            # Load detector models
            self.detector.load_models(model_path)
            
            print(f"Models loaded successfully from {model_path}")
            return True
        except Exception as e:
            print(f"Error loading models: {str(e)}")
            return False
    
    def process_event(self, event_json):
        """Process a single event and return anomaly result"""
        # Convert to flat dictionary
        flat_event = self.preprocessor.flatten_json(event_json)
        
        # Convert to DataFrame (single row)
        event_df = pd.DataFrame([flat_event])
        
        # Fill missing values
        event_df = self.preprocessor._fill_missing_values(event_df)
        
        # Transform features
        try:
            event_transformed = self.preprocessor.transform(event_df)
        except Exception as e:
            # Handle missing columns gracefully
            print(f"Warning: {str(e)}")
            # Use only available columns
            common_cols = list(set(event_df.columns) & set(self.preprocessor.numerical_cols + self.preprocessor.categorical_cols))
            event_df = event_df[common_cols]
            # Fill missing columns with zeros
            event_transformed = np.zeros((1, self.detector.input_dim))
        
        # Update internal state for temporal analysis
        self.recent_observations.append(event_transformed[0])
        if len(self.recent_observations) > self.window_size:
            self.recent_observations.pop(0)
        
        # Create sequence for temporal models if available
        event_sequence = None
        if self.sequence_length is not None and len(self.recent_observations) >= self.sequence_length:
            event_sequence = np.array([self.recent_observations[-self.sequence_length:]])
        
        # Get anomaly scores
        scores = self.detector.predict_anomaly_scores(event_transformed, event_sequence)
        
        # Make prediction
        is_anomaly = self.detector.predict(event_transformed, event_sequence)[0]
        
        # Format result
        result = {
            "is_anomaly": bool(is_anomaly),
            "anomaly_scores": {k: float(v[0]) for k, v in scores.items()},
            "thresholds": {k: float(v) for k, v in self.detector.thresholds.items()},
            "timestamp": datetime.now().isoformat()
        }
        
        # Add explanation if it's an anomaly
        if is_anomaly:
            # Get feature names (may be limited in scope for inference engine)
            feature_names = self.preprocessor.feature_names if hasattr(self.preprocessor, 'feature_names') else None
            
            if feature_names:
                # Get top contributing features
                feature_contributions = {}
                if 'autoencoder' in self.detector.models:
                    preds = self.detector.models['autoencoder'].predict(event_transformed)
                    feature_errors = np.power(event_transformed[0] - preds[0], 2)
                    
                    # Get top 5 contributing features
                    top_indices = np.argsort(feature_errors)[-5:][::-1]
                    for idx in top_indices:
                        if idx < len(feature_names):
                            feature_contributions[feature_names[idx]] = float(feature_errors[idx])
                
                result["explanation"] = {
                    "top_contributing_features": feature_contributions
                }
                
        return result
    
    def batch_process(self, events_json_list):
        """Process a batch of events"""
        results = []
        for event_json in events_json_list:
            results.append(self.process_event(event_json))
        return results

# Example usage in a FastAPI backend
def create_fastapi_app():
    """Create FastAPI application for serving the model"""
    from fastapi import FastAPI, WebSocket, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    import asyncio
    import socketio
    import json
    
    # Initialize inference engine
    inference_engine = CyberThreatInferenceEngine()
    
    # Create FastAPI app
    app = FastAPI(title="Cyber Threat Anomaly Detection API")
    
    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # In production, restrict this to your frontend domain
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Create Socket.IO server
    sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins=[])
    socket_app = socketio.ASGIApp(sio)
    
    # Mount Socket.IO app
    app.mount("/socket.io", socket_app)
    
    @app.get("/")
    def read_root():
        return {"status": "online", "model": "Cyber Threat Anomaly Detection"}
    
    @app.post("/predict")
    def predict_single(event: dict):
        try:
            result = inference_engine.process_event(event)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")
    
    @app.post("/batch_predict")
    def predict_batch(events: list):
        try:
            results = inference_engine.batch_process(events)
            return {"results": results}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Batch prediction error: {str(e)}")
    
    @sio.on('connect')
    async def connect(sid, environ):
        print(f"Client connected: {sid}")
    
    @sio.on('disconnect')
    def disconnect(sid):
        print(f"Client disconnected: {sid}")
    
    @sio.on('detect_threat')
    async def detect_threat(sid, data):
        try:
            event = json.loads(data) if isinstance(data, str) else data
            result = inference_engine.process_event(event)
            await sio.emit('threat_result', result, room=sid)
        except Exception as e:
            await sio.emit('error', {"message": str(e)}, room=sid)
    
    return app

# Prepare for electron deployment
def prepare_electron_deploy():
    """Prepare models for deployment in Electron application"""
    from pathlib import Path
    import shutil
    
    # Create electron ml directory
    electron_dir = Path("electron_app/ml")
    electron_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy required model files
    for file in ["autoencoder_quantized.tflite", "config.joblib", "preprocessor.joblib"]:
        src = Path(f"models/{file}")
        if src.exists():
            shutil.copy(src, electron_dir / file)
    
    print(f"Models prepared for Electron deployment at {electron_dir}")
    
    # Create sample implementation for loading models in Electron
    with open(electron_dir / "model_loader.js", "w") as f:
        f.write("""
// Sample code for loading models in Electron
const fs = require('fs');
const path = require('path');
const tf = require('@tensorflow/tfjs-node');
const { exec } = require('child_process');

class CyberThreatDetector {
  constructor() {
    this.modelPath = path.join(__dirname, 'autoencoder_quantized.tflite');
    this.configPath = path.join(__dirname, 'config.joblib');
    this.preprocessorPath = path.join(__dirname, 'preprocessor.joblib');
    this.model = null;
    this.config = null;
  }

  async loadModel() {
    try {
      // For TFLite models, we use a Python subprocess
      // In production, you'd want to use tfjs-node or compile for your platform
      console.log('Loading model from:', this.modelPath);
      this.model = await tf.loadLayersModel(`file://${this.modelPath}`);
      
      // In real implementation, load joblib files using appropriate method
      console.log('Model loaded successfully');
      return true;
    } catch (error) {
      console.error('Error loading model:', error);
      return false;
    }
  }

  async predict(event) {
    // Implementation would preprocess event and call the model
    console.log('Predicting for event:', event);
    return {
      is_anomaly: false,
      confidence: 0.1
    };
  }
}

module.exports = CyberThreatDetector;
""")
    
    print("Created sample model_loader.js for Electron")

# Main execution for Google Colab
def main():
    """Main function to run in Google Colab"""
    # Display intro
    print("=" * 80)
    print("Next-Generation Cyber Threat Anomaly Detection")
    print("=" * 80)
    
    # Create synthetic data for demonstration
    print("\nGenerating synthetic dataset...")
    
    # Create normal data
    num_normal = 1000
    normal_data = []
    for i in range(num_normal):
        normal_record = {
            "threat_summary": {
                "risk_level": np.random.choice(["low", "medium"], p=[0.8, 0.2]),
                "threat_score": np.random.uniform(0, 40),
                "contributing_indicators": []
            },
            "network_details": {
                "timestamp": (datetime.now() - pd.Timedelta(seconds=np.random.randint(0, 86400))).isoformat(),
                "source_ip": f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                "destination_ip": f"172.{np.random.randint(16, 32)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                "protocol": np.random.choice(["TCP", "UDP", "HTTP", "HTTPS"], p=[0.4, 0.1, 0.3, 0.2])
            },
            "security_headers_status": np.random.choice(["secure", "partial", "missing"], p=[0.7, 0.2, 0.1]),
            "behavioral_indicators": {
                "request_frequency": np.random.uniform(0.1, 5),
                "bytes_transferred": np.random.uniform(100, 10000),
                "session_duration": np.random.uniform(1, 300)
            },
            "content_analysis": {
                "mime_type": np.random.choice(["text/html", "application/json", "image/jpeg"]),
                "packet_size": np.random.uniform(50, 1500),
                "entropy": np.random.uniform(0.1, 0.6)
            },
            "header_analysis": {
                "user_agent": np.random.choice(["Chrome", "Firefox", "Safari", "Bot"], p=[0.4, 0.3, 0.2, 0.1]),
                "accept_language": np.random.choice(["en-US", "en-GB", "fr", "de", "zh-CN"]),
                "cache_control": np.random.choice(["private", "public", "no-cache"], p=[0.5, 0.3, 0.2])
            }
        }
        
        # Add random number of contributing indicators
        num_indicators = np.random.randint(0, 3)
        for _ in range(num_indicators):
            normal_record["threat_summary"]["contributing_indicators"].append(
                np.random.choice(["header_missing", "unusual_encoding", "poor_reputation"])
            )
            
        normal_data.append(normal_record)
    
    # Create attack data
    num_attacks = 100
    attack_data = []
    for i in range(num_attacks):
        attack_type = np.random.choice(["data_exfiltration", "scanning", "injection", "unusual_protocol"])
        
        attack_record = {
            "threat_summary": {
                "risk_level": np.random.choice(["medium", "high"], p=[0.3, 0.7]),
                "threat_score": np.random.uniform(60, 100),
                "contributing_indicators": []
            },
            "network_details": {
                "timestamp": (datetime.now() - pd.Timedelta(seconds=np.random.randint(0, 86400))).isoformat(),
                "source_ip": f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                "destination_ip": f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                "protocol": np.random.choice(["TCP", "UDP", "HTTP", "HTTPS", "ICMP"])
            },
            "security_headers_status": np.random.choice(["secure", "partial", "missing"], p=[0.1, 0.3, 0.6]),
            "behavioral_indicators": {
                "request_frequency": np.random.uniform(5, 50) if attack_type == "scanning" else np.random.uniform(0.1, 5),
                "bytes_transferred": np.random.uniform(10000, 100000) if attack_type == "data_exfiltration" else np.random.uniform(100, 10000),
                "session_duration": np.random.uniform(1, 30) if attack_type == "scanning" else np.random.uniform(300, 3600) 
            },
            "content_analysis": {
                "mime_type": np.random.choice(["text/