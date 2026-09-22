from pathlib import Path
import importlib.util

import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = ROOT / 'ml' / 'datasets.csv'
FEATURE_FILE = ROOT / 'backend' / 'feature-extractor.py'
MODEL_PATH = ROOT / 'backend' / 'model.pkl'

spec = importlib.util.spec_from_file_location('feature_extractor', FEATURE_FILE)
feature_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feature_module)
extract_features = feature_module.extract_features

# 1. Load dataset
# Dataset columns: 'url' and 'status' with values 'phishing' or 'legitimate'
df = pd.read_csv(DATASET_PATH)
df = df[['url', 'status']].dropna().copy()
df['label'] = df['status'].map({'phishing': 1, 'legitimate': 0})

df = df[df['label'].notna()].reset_index(drop=True)

# 2. Extract features for all URLs
feature_list = df['url'].apply(extract_features).tolist()
X = pd.DataFrame(feature_list)
y = df['label']

# 3. Train/Test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Train Random Forest Classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 5. Evaluate performance
y_pred = model.predict(X_test)
print('Accuracy:', accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# 6. Save model artifact
joblib.dump(model, MODEL_PATH)
print(f'Model saved to {MODEL_PATH}')