from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
from feature_extractor import extract_features

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests from frontend UI

# Load trained pipeline
try:
    model = joblib.load('model.pkl')
except Exception as e:
    raise RuntimeError(f"Failed to load model.pkl: {e}")

# Domain Authority Whitelist to prevent false positives on major platforms
WHITELIST = ['google.com', 'github.com', 'microsoft.com', 'amazon.com', 'wikipedia.org']


@app.route('/predict', methods=['POST'])
def predict():
    # request.get_json() returns None (instead of raising) if the body
    # isn't valid JSON or Content-Type isn't set — guard against that
    # before calling .get() on it, which was the main crash point.
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({'error': 'Request body must be valid JSON'}), 400

    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    # Ensure URL protocol is present for parsing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # 1. Check Whitelist
    for domain in WHITELIST:
        if domain in url.lower():
            return jsonify({
                'url': url,
                'status': 'Safe',
                'confidence_score': 0.0,
                'risk_level': 'None (Whitelisted Domain)',
                'flags': []
            })

    # 2. Extract Features
    try:
        raw_features = extract_features(url)
        features_df = pd.DataFrame([raw_features])
    except Exception as e:
        return jsonify({'error': f'Feature extraction failed: {e}'}), 500

    # 3. Model Inference
    try:
        prediction = model.predict(features_df)[0]
        probabilities = model.predict_proba(features_df)[0]
        malicious_probability = float(probabilities[1])
    except Exception as e:
        return jsonify({'error': f'Model inference failed: {e}'}), 500

    # 4. Generate Threat Flags
    # Use .get() with defaults instead of direct indexing so a missing
    # key from extract_features() raises no KeyError.
    flags = []
    if raw_features.get('has_ip_address'):
        flags.append("Raw IP address used as hostname")
    if raw_features.get('is_shortened'):
        flags.append("URL redirection/shortener detected")
    if raw_features.get('suspicious_keyword_count', 0) > 0:
        flags.append("Contains sensitive action keywords (login, verify, update)")
    if not raw_features.get('is_https', True):
        flags.append("Insecure HTTP protocol")

    # 5. Formulate Result
    status = "Malicious" if prediction == 1 or malicious_probability > 0.6 else "Safe"
    risk_level = "High" if malicious_probability > 0.75 else ("Medium" if malicious_probability > 0.4 else "Low")

    return jsonify({
        'url': url,
        'status': status,
        'confidence_score': round(malicious_probability * 100, 2),
        'risk_level': risk_level,
        'flags': flags
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)