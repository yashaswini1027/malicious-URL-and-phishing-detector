import re
import math
import socket
from datetime import datetime
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

try:
    import whois
except ImportError:
    whois = None

try:
    import tldextract
except ImportError:
    tldextract = None

REQUEST_TIMEOUT = 5
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

SHORTENING_SERVICES = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs",
    re.I
)
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'account', 'update', 'banking', 'secure',
    'signin', 'ebayisapi', 'paypal', 'confirm', 'password'
]
SUSPICIOUS_TLDS = {
    'zip', 'review', 'country', 'kim', 'cricket', 'science', 'work',
    'party', 'gq', 'link', 'tk', 'cf', 'ml', 'ga', 'top', 'xyz'
}
KNOWN_BRANDS = [
    'paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook',
    'netflix', 'instagram', 'whatsapp', 'bank', 'chase', 'wellsfargo'
]
DANGEROUS_EXTENSIONS = {'exe', 'zip', 'scr', 'bat', 'jar', 'apk', 'msi', 'js'}


# ---------- helpers ----------

def _get_domain_parts(hostname):
    """Return (subdomain, domain, tld) robustly, falling back to a simple split."""
    if tldextract:
        ext = tldextract.extract(hostname or '')
        return ext.subdomain, ext.domain, ext.suffix
    parts = (hostname or '').split('.')
    if len(parts) >= 3:
        return '.'.join(parts[:-2]), parts[-2], parts[-1]
    if len(parts) == 2:
        return '', parts[0], parts[1]
    return '', hostname or '', ''


def _tokenize(text):
    return [w for w in re.split(r'[^a-zA-Z0-9]', text or '') if w]


def _word_stats(words):
    if not words:
        return 0, 0, 0
    lengths = [len(w) for w in words]
    return min(lengths), max(lengths), sum(lengths) / len(lengths)


def _char_repeat(text):
    if not text:
        return 0
    max_run = run = 1
    for i in range(1, len(text)):
        if text[i] == text[i - 1]:
            run += 1
            max_run = max(max_run, run)
        else:
            run = 1
    return max_run


def _shannon_entropy(text):
    if not text:
        return 0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _fetch_page(url):
    """Fetch the page once; return (response, soup) or (None, None) on any failure."""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        soup = BeautifulSoup(resp.text, 'html.parser')
        return resp, soup
    except Exception:
        return None, None


def _is_external(link_netloc, base_domain):
    if not link_netloc:
        return False
    return base_domain.lower() not in link_netloc.lower()


# ---------- main entry point ----------

def extract_features(url: str) -> dict:
    features = {}

    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0]
    path = parsed.path or ''
    subdomain, domain, tld = _get_domain_parts(hostname)
    base_domain = f"{domain}.{tld}" if tld else domain

    # --- 0-22: structural / symbol counts ---
    features['length_url'] = len(url)
    features['length_hostname'] = len(hostname)
    ip_pattern = r"^(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])$"
    features['ip'] = 1 if re.match(ip_pattern, hostname) else 0
    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_at'] = url.count('@')
    features['nb_qm'] = url.count('?')
    features['nb_and'] = url.count('&')
    features['nb_or'] = url.count('|')
    features['nb_eq'] = url.count('=')
    features['nb_underscore'] = url.count('_')
    features['nb_tilde'] = url.count('~')
    features['nb_percent'] = url.count('%')
    features['nb_slash'] = url.count('/')
    features['nb_star'] = url.count('*')
    features['nb_colon'] = url.count(':')
    features['nb_comma'] = url.count(',')
    features['nb_semicolumn'] = url.count(';')
    features['nb_dollar'] = url.count('$')
    features['nb_space'] = url.count(' ') + url.count('%20')
    features['nb_www'] = url.lower().count('www')
    features['nb_com'] = url.lower().count('.com')
    features['nb_dslash'] = url.count('//') - 1 if url.count('//') > 0 else 0

    # --- 23-38: security / domain indicators ---
    features['http_in_path'] = 1 if 'http' in path.lower() else 0
    features['https_token'] = 1 if 'https' in hostname.lower() else 0
    digits_url = sum(c.isdigit() for c in url)
    digits_host = sum(c.isdigit() for c in hostname)
    features['ratio_digits_url'] = digits_url / len(url) if url else 0
    features['ratio_digits_host'] = digits_host / len(hostname) if hostname else 0
    features['punycode'] = 1 if 'xn--' in hostname.lower() else 0
    features['port'] = 1 if parsed.port else 0
    features['tld_in_path'] = 1 if tld and tld.lower() in path.lower() else 0
    features['tld_in_subdomain'] = 1 if tld and tld.lower() in subdomain.lower() else 0
    features['abnormal_subdomain'] = 1 if re.search(r'w-w-w|w\d+w', subdomain.lower()) else 0
    features['nb_subdomains'] = subdomain.count('.') + 1 if subdomain else 0
    features['prefix_suffix'] = 1 if '-' in domain else 0
    features['random_domain'] = 1 if _shannon_entropy(domain) > 3.5 else 0
    features['shortening_service'] = 1 if SHORTENING_SERVICES.search(url) else 0
    last_segment = path.rstrip('/').split('/')[-1] if path else ''
    ext = last_segment.split('.')[-1].lower() if '.' in last_segment else ''
    features['path_extension'] = 1 if ext in DANGEROUS_EXTENSIONS else 0
    features['nb_redirection'] = path.count('//')
    features['nb_external_redirection'] = 0  # filled in below if page fetch succeeds

    # --- 39-49: word-based stats ---
    raw_words = _tokenize(url)
    host_words = _tokenize(hostname)
    path_words = _tokenize(path)
    features['length_words_raw'] = len(raw_words)
    features['char_repeat'] = _char_repeat(url)
    s_raw, l_raw, a_raw = _word_stats(raw_words)
    s_host, l_host, a_host = _word_stats(host_words)
    s_path, l_path, a_path = _word_stats(path_words)
    features['shortest_words_raw'] = s_raw
    features['shortest_word_host'] = s_host
    features['shortest_word_path'] = s_path
    features['longest_words_raw'] = l_raw
    features['longest_word_host'] = l_host
    features['longest_word_path'] = l_path
    features['avg_words_raw'] = a_raw
    features['avg_word_host'] = a_host
    features['avg_word_path'] = a_path

    # --- 50-55: keyword / brand / tld hints ---
    features['phish_hints'] = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower())
    features['domain_in_brand'] = 1 if any(b in domain.lower() for b in KNOWN_BRANDS) else 0
    features['brand_in_subdomain'] = 1 if any(b in subdomain.lower() for b in KNOWN_BRANDS) else 0
    features['brand_in_path'] = 1 if any(b in path.lower() for b in KNOWN_BRANDS) else 0
    features['suspecious_tld'] = 1 if tld.lower() in SUSPICIOUS_TLDS else 0
    features['statistical_report'] = 0  # no blacklist feed wired up

    # --- 56-79: page-content-based features (require fetching the live page) ---
    resp, soup = _fetch_page(url)

    if resp is not None and soup is not None:
        features['nb_external_redirection'] = sum(
            1 for r in resp.history if _is_external(urlparse(r.url).netloc, base_domain)
        )

        links = soup.find_all('a', href=True)
        total_links = len(links) or 1
        int_links = sum(1 for a in links if not _is_external(urlparse(a['href']).netloc, base_domain))
        ext_links = sum(1 for a in links if _is_external(urlparse(a['href']).netloc, base_domain))
        null_links = sum(1 for a in links if a['href'].strip() in ('', '#', 'javascript:void(0)'))

        features['nb_hyperlinks'] = len(links)
        features['ratio_intHyperlinks'] = int_links / total_links
        features['ratio_extHyperlinks'] = ext_links / total_links
        features['ratio_nullHyperlinks'] = null_links / total_links

        css_links = soup.find_all('link', rel='stylesheet', href=True)
        features['nb_extCSS'] = sum(
            1 for c in css_links if _is_external(urlparse(c['href']).netloc, base_domain)
        )

        features['ratio_intRedirection'] = 0
        features['ratio_extRedirection'] = 0
        features['ratio_intErrors'] = 0
        features['ratio_extErrors'] = 0

        forms = soup.find_all('form')
        features['login_form'] = 1 if any(f.find('input', {'type': 'password'}) for f in forms) else 0

        favicon = soup.find('link', rel=lambda v: v and 'icon' in v.lower())
        features['external_favicon'] = 1 if favicon and _is_external(
            urlparse(favicon.get('href', '')).netloc, base_domain
        ) else 0

        tag_links = soup.find_all(['script', 'link', 'meta'])
        features['links_in_tags'] = len(tag_links)

        features['submit_email'] = 1 if any(
            'mailto:' in (f.get('action') or '') for f in forms
        ) else 0

        media = soup.find_all(['img', 'video', 'audio'], src=True)
        total_media = len(media) or 1
        int_media = sum(1 for m in media if not _is_external(urlparse(m['src']).netloc, base_domain))
        ext_media = sum(1 for m in media if _is_external(urlparse(m['src']).netloc, base_domain))
        features['ratio_intMedia'] = int_media / total_media
        features['ratio_extMedia'] = ext_media / total_media

        features['sfh'] = 1 if any(
            (f.get('action') or '').strip() in ('', '#', 'about:blank') for f in forms
        ) else 0

        features['iframe'] = 1 if soup.find('iframe') else 0
        html_lower = resp.text.lower()
        features['popup_window'] = 1 if 'window.open(' in html_lower else 0

        anchors = soup.find_all('a')
        total_anchors = len(anchors) or 1
        safe = sum(
            1 for a in anchors
            if (a.get('href') or '').strip() in ('#', 'javascript:void(0)', '')
        )
        features['safe_anchor'] = safe / total_anchors

        features['onmouseover'] = 1 if 'onmouseover' in html_lower and 'window.status' in html_lower else 0
        features['right_clic'] = 1 if 'contextmenu' in html_lower or 'event.button==2' in html_lower else 0

        title = soup.title.string.strip() if soup.title and soup.title.string else ''
        features['empty_title'] = 1 if not title else 0
        features['domain_in_title'] = 1 if domain.lower() in title.lower() else 0
        features['domain_with_copyright'] = 1 if (
            '©' in resp.text or 'copyright' in html_lower
        ) and domain.lower() in html_lower else 0
    else:
        # Page unreachable (offline, blocked, timed out) — safe zero defaults
        for key in [
            'nb_hyperlinks', 'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks',
            'nb_extCSS', 'ratio_intRedirection', 'ratio_extRedirection', 'ratio_intErrors',
            'ratio_extErrors', 'login_form', 'external_favicon', 'links_in_tags', 'submit_email',
            'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe', 'popup_window', 'safe_anchor',
            'onmouseover', 'right_clic', 'empty_title', 'domain_in_title', 'domain_with_copyright'
        ]:
            features[key] = 0

    # --- 80-82: WHOIS-based domain age / registration ---
    features['whois_registered_domain'] = 0
    features['domain_registration_length'] = 0
    features['domain_age'] = 0
    if whois is not None:
        try:
            w = whois.whois(base_domain)
            creation = w.creation_date
            expiration = w.expiration_date
            if isinstance(creation, list):
                creation = creation[0]
            if isinstance(expiration, list):
                expiration = expiration[0]
            if creation:
                features['whois_registered_domain'] = 1
                features['domain_age'] = (datetime.now() - creation).days
            if creation and expiration:
                features['domain_registration_length'] = (expiration - creation).days
        except Exception:
            pass  # keep zero defaults — WHOIS server may be unreachable/rate-limited

    # --- 83: dns_record ---
    try:
        socket.gethostbyname(hostname)
        features['dns_record'] = 1
    except Exception:
        features['dns_record'] = 0

    # --- 84-86: services that are discontinued/unreliable today ---
    # Alexa (web_traffic) shut down in 2022; live Google-index checking and
    # third-party PageRank APIs are not reliably available for free at request
    # time. These are set to neutral defaults rather than faked values.
    features['web_traffic'] = -1
    features['google_index'] = 0
    features['page_rank'] = 0

    return features