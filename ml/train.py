import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from feature_extractor import extract_features

# 1. Load dataset (Assumes columns: 'url' and 'label' where 1=phishing, 0=safe)
df = pd.read_csv('url_dataset.csv')

# 2. Extract features for all URLs
feature_list = df['url'].apply(extract_features).tolist()
X = pd.DataFrame(feature_list)
y = df['label']

# 3. Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Train Random Forest Classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 5. Evaluate Performance
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# 6. Save Model Artifact
joblib.dump(model, '../backend/model.pkl')
print("Model saved to backend/model.pkl")