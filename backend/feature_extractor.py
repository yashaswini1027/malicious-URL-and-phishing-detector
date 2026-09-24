import re
from urllib.parse import urlparse

# Common URL shorteners used in phishing
SHORTENING_SERVICES = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs"

# Keywords frequently seen in phishing links
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'account', 'update', 'banking', 'secure', 'signin', 'ebayisapi', 'paypal']

def extract_features(url: str) -> dict:
    features = {}
    parsed = urlparse(url)
    
    # 1. Structural Length Metrics
    features['url_length'] = len(url)
    features['hostname_length'] = len(parsed.netloc)
    features['path_length'] = len(parsed.path)
    
    # 2. Suspicious Symbol Counts
    features['count_dots'] = url.count('.')
    features['count_hyphens'] = url.count('-')
    features['count_at'] = url.count('@')
    features['count_question'] = url.count('?')
    features['count_equal'] = url.count('=')
    features['count_slash'] = url.count('/')
    
    # 3. Security & Domain Indicators
    features['is_https'] = 1 if parsed.scheme == 'https' else 0
    
    # IP address instead of domain name
    ip_pattern = r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])"
    features['has_ip_address'] = 1 if re.search(ip_pattern, parsed.netloc) else 0
    
    # Shortened URL check
    features['is_shortened'] = 1 if re.search(SHORTENING_SERVICES, url, flags=re.I) else 0
    
    # Suspicious Keywords presence
    features['suspicious_keyword_count'] = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower())
    
    return features