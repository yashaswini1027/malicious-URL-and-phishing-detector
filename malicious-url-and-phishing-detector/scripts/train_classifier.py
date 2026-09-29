from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import pandas as pd
import joblib
import os

# Load dataset
def load_data(file_path):
    data = pd.read_csv(file_path)
    return data

# Preprocess data
def preprocess_data(data):
    # Assuming the last column is the target variable
    X = data.iloc[:, :-1]
    y = data.iloc[:, -1]
    return X, y

# Train classifier
def train_classifier(X, y):
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    return model

# Save model
def save_model(model, model_path):
    joblib.dump(model, model_path)

def main():
    # Define file paths
    data_file_path = 'path/to/your/dataset.csv'  # Update with your dataset path
    model_save_path = 'backend/models/lightweight_classifier.pkl'

    # Load and preprocess data
    data = load_data(data_file_path)
    X, y = preprocess_data(data)

    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train the classifier
    model = train_classifier(X_train, y_train)

    # Evaluate the model
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))
    print(f'Accuracy: {accuracy_score(y_test, y_pred)}')

    # Save the trained model
    save_model(model, model_save_path)

if __name__ == '__main__':
    main()