import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, jsonify, request, send_from_directory

FRONTEND_DIR = Path(__file__).resolve().parent.parent / 'frontend'
app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path='')

WHITELIST = ('google.com', 'github.com', 'microsoft.com', 'amazon.com', 'wikipedia.org')
SHORTENERS = ('bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'ow.ly', 'buff.ly')
SUSPICIOUS_TLDS = {'zip', 'work', 'party', 'gq', 'tk', 'cf', 'ml', 'ga', 'top', 'xyz'}
BRANDS = ('paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook', 'netflix', 'instagram')
SUSPICIOUS_TERMS = ('login', 'verify', 'account', 'update', 'banking', 'secure', 'signin', 'confirm', 'password')


def analyze_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or '').lower().rstrip('.')
        parsed.port
    except ValueError:
        raise ValueError('Enter a valid URL.') from None

    if not hostname:
        raise ValueError('Enter a valid URL with a hostname.')

    if any(hostname == domain or hostname.endswith('.' + domain) for domain in WHITELIST):
        return {
            'url': url,
            'status': 'Safe',
            'confidence_score': 0,
            'risk_level': 'None (Whitelisted Domain)',
            'flags': [],
            'analysis_mode': 'offline heuristic',
        }

    score = 0
    flags = []

    try:
        ipaddress.ip_address(hostname)
        score += 30
        flags.append('URL uses an IP address instead of a domain name')
    except ValueError:
        pass

    if any(hostname == domain or hostname.endswith('.' + domain) for domain in SHORTENERS):
        score += 25
        flags.append('URL uses a link-shortening service')

    if 'xn--' in hostname:
        score += 25
        flags.append('Domain uses punycode encoding')

    terms_found = [term for term in SUSPICIOUS_TERMS if term in url.lower()]
    if terms_found:
        score += min(12 * len(terms_found), 36)
        flags.append('URL contains sensitive action terms: ' + ', '.join(terms_found))

    brand_found = [brand for brand in BRANDS if brand in hostname]
    if brand_found:
        score += 25
        flags.append('Domain contains a well-known brand name')

    tld = hostname.rsplit('.', 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        score += 20
        flags.append('Domain uses a top-level domain often associated with abuse')

    if parsed.username is not None:
        score += 25
        flags.append('URL contains user information before the hostname')

    if len(hostname.split('.')) >= 5:
        score += 15
        flags.append('Domain has an unusually deep subdomain structure')

    if hostname.count('-') >= 2:
        score += 10
        flags.append('Domain contains multiple hyphens')

    if len(url) > 120:
        score += 10
        flags.append('URL is unusually long')

    score = min(score, 100)
    status = 'Malicious' if score >= 35 else 'Safe'
    risk_level = 'High' if score >= 60 else ('Medium' if score >= 35 else 'Low')

    return {
        'url': url,
        'status': status,
        'confidence_score': score,
        'risk_level': risk_level,
        'flags': flags,
        'analysis_mode': 'offline heuristic',
    }


@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Request body must be a JSON object.'}), 400

    url = data.get('url', '')
    if not isinstance(url, str) or not url.strip():
        return jsonify({'error': 'URL is required.'}), 400

    try:
        return jsonify(analyze_url(url.strip()))
    except ValueError as error:
        return jsonify({'error': str(error)}), 400


@app.route('/')
def home():
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/favicon.ico')
def favicon():
    return '', 204


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)