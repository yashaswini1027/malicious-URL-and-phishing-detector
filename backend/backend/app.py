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
        # Guarantee column order/names match exactly what the model was
        # trained on, regardless of dict insertion order.
        features_df = features_df.reindex(columns=model.feature_names_in_)
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
    flags = []
    if raw_features.get('ip'):
        flags.append("Raw IP address used as hostname")
    if raw_features.get('shortening_service'):
        flags.append("URL redirection/shortener detected")
    if raw_features.get('phish_hints', 0) > 0:
        flags.append("Contains sensitive action keywords (login, verify, update)")
    if raw_features.get('login_form'):
        flags.append("Page contains a login form")
    if raw_features.get('iframe'):
        flags.append("Page contains hidden iframe(s)")
    if raw_features.get('punycode'):
        flags.append("Domain uses punycode encoding (possible homograph attack)")
    if raw_features.get('suspecious_tld'):
        flags.append("Domain uses a top-level domain commonly linked to abuse")

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


@app.route('/', methods=['GET'])
def home():
    return jsonify({'message': 'Phishing detector API is running. POST a URL to /predict.'})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)