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


def load_feature_extractor():
    if not FEATURE_FILE.exists():
        raise FileNotFoundError(f'Feature extractor not found: {FEATURE_FILE}')

    spec = importlib.util.spec_from_file_location('feature_extractor', FEATURE_FILE)
    if spec is None or spec.loader is None:
        raise ImportError(f'Unable to load feature extractor from {FEATURE_FILE}')

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.extract_features


def load_dataset():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f'Dataset not found: {DATASET_PATH}')

    df = pd.read_csv(DATASET_PATH, sep='\t', on_bad_lines='skip', engine='python')

    required_columns = {'url', 'status'}
    missing = required_columns - set(df.columns)
    if missing:
        raise ValueError(f'Dataset is missing required columns: {sorted(missing)}')

    df = df.dropna(subset=['url', 'status']).copy()
    df['status'] = df['status'].astype(str).str.strip().str.lower()
    df['label'] = df['status'].map({'phishing': 1, 'legitimate': 0})
    df = df[df['label'].notna()].reset_index(drop=True)
    return df


def main():
    load_feature_extractor()
    df = load_dataset()

    feature_columns = [col for col in df.columns if col not in {'url', 'status', 'label'}]
    if not feature_columns:
        raise ValueError('No feature columns found in the dataset. Expected columns besides url/status.')

    X = df[feature_columns].copy()
    for col in X.columns:
        X[col] = (
            X[col]
            .astype(str)
            .str.strip()
            .str.lower()
            .replace({'zero': '0', 'one': '1'})
        )
        X[col] = pd.to_numeric(X[col], errors='coerce')

    y = df['label']

    # 1. Train/Test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 2. Train Random Forest Classifier
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # 3. Evaluate performance
    y_pred = model.predict(X_test)
    print('Accuracy:', accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))

    # 4. Save model artifact
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f'Model saved to {MODEL_PATH}')


if __name__ == '__main__':
    main()


