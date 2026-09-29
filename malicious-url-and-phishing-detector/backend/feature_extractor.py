from sklearn.feature_extraction.text import CountVectorizer
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse

class ThreatAnalyzer:
    def __init__(self, model_path):
        self.model = joblib.load(model_path)
        self.vectorizer = CountVectorizer()

    def extract_url_features(self, url):
        parsed_url = urlparse(url)
        features = {
            'url_length': len(url),
            'num_subdomains': len(parsed_url.netloc.split('.')) - 2,
            'num_path_segments': len(parsed_url.path.split('/')) - 1,
            'has_ip_address': 1 if any(char.isdigit() for char in parsed_url.netloc) else 0,
            'has_https': 1 if parsed_url.scheme == 'https' else 0,
            'num_query_parameters': len(parsed_url.query.split('&')) if parsed_url.query else 0,
            'num_special_chars': sum(not c.isalnum() for c in url)
        }
        return features

    def predict(self, url):
        features = self.extract_url_features(url)
        features_df = pd.DataFrame([features])
        prediction = self.model.predict(features_df)
        probabilities = self.model.predict_proba(features_df)
        return prediction[0], probabilities[0]

    def analyze_page_content(self, content):
        # Placeholder for analyzing page content
        # This can be expanded to include more sophisticated analysis
        return "Content analysis not implemented yet"

# Example usage:
# analyzer = ThreatAnalyzer('path/to/your/model.pkl')
# prediction, probabilities = analyzer.predict('http://example.com')