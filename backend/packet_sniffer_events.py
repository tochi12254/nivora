# packet_sniffer_events.py
import logging
from socketio import AsyncNamespace
from multiprocessing import Manager, Queue
from typing import Any, Dict

logger = logging.getLogger(__name__)


class PacketSnifferNamespace(AsyncNamespace):
    def __init__(self, namespace: str, sio_queue: Queue):
        super().__init__(namespace)
        self.sio_queue = sio_queue
# === CyberWatch CICIDS2017 Data Preparation Script ===

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.preprocessing import RobustScaler
from sklearn.feature_selection import SelectKBest, f_classif
import warnings

warnings.filterwarnings("ignore")

# Copy full dataset
df = data.copy()

# Drop original 'Label' if present
if "Label" in df.columns:
    df.drop("Label", axis=1, inplace=True)

print("\n=== Dataset Overview ===")
print(f"Shape: {df.shape}")
print(f"Columns: {df.columns.tolist()}")
print(f"\nAttack type distribution:")
print(df["Attack_Type"].value_counts())

# Clean column names
df.columns = df.columns.str.strip()

# Drop columns with constant values (1 unique)
num_unique = df.nunique()
constant_cols = num_unique[num_unique == 1].index.tolist()
if constant_cols:
    print(f"\nDropping {len(constant_cols)} constant columns:")
    print(constant_cols)
    df.drop(columns=constant_cols, inplace=True)

# Ensure all remaining features are numeric
non_numeric = df.select_dtypes(exclude=["number"]).columns.tolist()
non_feature_cols = ["Attack_Type"]
non_numeric = [col for col in non_numeric if col not in non_feature_cols]
if non_numeric:
    print(f"\nDropping non-numeric columns: {non_numeric}")
    df.drop(columns=non_numeric, inplace=True)

# Handle missing/infinite values
print("\n=== Handling Inf & Missing ===")
df.replace([np.inf, -np.inf], np.nan, inplace=True)
missing = df.isnull().sum()
missing = missing[missing > 0]
if not missing.empty:
    print(f"Missing values found in: {missing.index.tolist()}")
    df.fillna(df.median(), inplace=True)
else:
    print("No missing values or inf detected.")

# Drop duplicates
before = df.shape[0]
df.drop_duplicates(inplace=True)
print(f"\nDropped {before - df.shape[0]} duplicate rows.")

# === Scaling ===
print("\n=== Robust Scaling Features ===")
features = df.drop("Attack_Type", axis=1)
attacks = df["Attack_Type"]

scaler = RobustScaler()
scaled_features = scaler.fit_transform(features)
scaled_df = pd.DataFrame(scaled_features, columns=features.columns)
scaled_df["Attack_Type"] = attacks.values

# === Feature Selection ===
print("\n=== Selecting Top Features ===")
X = scaled_df.drop("Attack_Type", axis=1)
y = scaled_df["Attack_Type"]

# Convert multi-class target to numeric temporarily for feature selection
y_for_selection = y.factorize()[0]  # numeric version of Attack_Type
selector = SelectKBest(score_func=f_classif, k=40)
X_selected = selector.fit_transform(X, y_for_selection)
selected_features = X.columns[selector.get_support(indices=True)].tolist()

print(f"Top {len(selected_features)} selected features:")
for i, col in enumerate(selected_features, 1):
    print(f"  {i}. {col}")

# Final dataset with selected features
final_df = scaled_df[selected_features + ["Attack_Type"]]

# Save cleaned dataset
output_path = "/content/CICIDS2017_preprocessed.csv"
final_df.to_csv(output_path, index=False)
print(f"\n✅ Preprocessed dataset saved to: {output_path}")

# Save selected feature list
features_path = "/content/selected_features.txt"
with open(features_path, "w") as f:
    for feat in selected_features:
        f.write(f"{feat}\n")
print(f"✅ Selected feature list saved to: {features_path}")

# Final Stats
print("\n=== Final Dataset Stats ===")
print(f"Shape: {final_df.shape}")
print(f"Feature Count: {len(selected_features)}")
print("Attack Distribution:")
print(final_df["Attack_Type"].value_counts())

# Plot
plt.figure(figsize=(12, 6))
final_df["Attack_Type"].value_counts().plot(kind="bar")
plt.title("Attack Distribution in Preprocessed Dataset")
plt.xlabel("Attack Type")
plt.ylabel("Sample Count")
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

print("\n=== ✅ Data Preparation Complete ===")
print("Next steps:")
print("1. Train one model per attack type (vs BENIGN)")
print("2. Save each model and scaler")
print("3. Deploy with real-time detection pipeline")
