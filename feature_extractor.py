import re
import math
import socket
import ssl
import urllib.parse
from datetime import datetime
import tldextract
import requests

SUSPICIOUS_TLDS = {
    'zip', 'mov', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'icu',
    'cn', 'ru', 'cc', 'fit', 'kim', 'rest', 'beauty', 'click', 'link', 'best',
    'online', 'site', 'monster', 'club', 'space', 'website', 'buzz', 'tech'
}

SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'ow.ly', 'buff.ly', 'adf.ly',
    'bit.do', 'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc', 'bc.vc', 'qr.ae'
}

SENSITIVE_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'bank', 'secure', 'update',
    'banking', 'wallet', 'support', 'confirm', 'credential', 'paypal',
    'apple', 'google', 'netflix', 'microsoft', 'meta', 'pay', 'auth',
    'recover', 'security', 'billing', 'password', 'service', 'validation'
]

TARGET_BRANDS = {
    'paypal': ['paypal.com', 'paypal.me'],
    'google': ['google.com', 'accounts.google.com', 'drive.google.com'],
    'apple': ['apple.com', 'icloud.com', 'appleid.apple.com'],
    'microsoft': ['microsoft.com', 'live.com', 'office.com', 'outlook.com'],
    'amazon': ['amazon.com', 'amazon.co.uk'],
    'netflix': ['netflix.com'],
    'facebook': ['facebook.com', 'fb.com'],
    'meta': ['meta.com', 'instagram.com'],
    'chase': ['chase.com'],
    'wellsfargo': ['wellsfargo.com'],
    'binance': ['binance.com'],
    'coinbase': ['coinbase.com'],
    'metamask': ['metamask.io']
}

def calculate_shannon_entropy(text):
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    for count in [text.count(c) for c in set(text)]:
        freq = count / length
        entropy -= freq * math.log2(freq)
    return round(entropy, 4)

def is_ip_address(hostname):
    # Check IPv4
    ipv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    if re.match(ipv4_pattern, hostname):
        return 1
    # Check hex or octal IP representation or IPv6
    if re.match(r'^0x[0-9a-fA-F]+$', hostname) or ':' in hostname:
        return 1
    return 0

def check_homoglyph_or_punycode(domain):
    if 'xn--' in domain:
        return 1
    # Check suspicious typosquatting lookalikes
    suspicious_patterns = [r'paypa[l1i]', r'goog[l1]e', r'rnicrosoft', r'app[l1]e']
    for pat in suspicious_patterns:
        if re.search(pat, domain.lower()) and not any(official in domain.lower() for official in ['paypal.com', 'google.com', 'microsoft.com', 'apple.com']):
            return 1
    return 0

def detect_brand_impersonation(url, domain):
    url_lower = url.lower()
    domain_lower = domain.lower()
    
    for brand, official_domains in TARGET_BRANDS.items():
        if brand in url_lower:
            # Check if actual domain matches official brand domains
            is_official = any(official in domain_lower for official in official_domains)
            if not is_official:
                return 1.0, brand
    return 0.0, None

def extract_url_features(url_string):
    """
    Extracts 22 numerical features for the Machine Learning model.
    """
    url = url_string.strip()
    if not url.startswith(('http://', 'https://')):
        # Default assume http for feature calculation if missing protocol
        full_url = 'http://' + url
    else:
        full_url = url

    parsed = urllib.parse.urlparse(full_url)
    ext = tldextract.extract(full_url)

    hostname = parsed.netloc.split(':')[0] if parsed.netloc else ''
    registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    subdomains = ext.subdomain

    # Feature 1: URL length
    url_length = len(full_url)

    # Feature 2: Domain length
    domain_length = len(registered_domain)

    # Feature 3: Subdomain count
    subdomain_count = len(subdomains.split('.')) if subdomains else 0

    # Feature 4: Has IP address
    has_ip = is_ip_address(hostname)

    # Feature 5: Entropy
    entropy = calculate_shannon_entropy(full_url)

    # Feature 6: Has @ symbol
    has_at_symbol = 1 if '@' in full_url else 0

    # Feature 7: Has double slash redirect in path
    has_double_slash = 1 if '//' in parsed.path else 0

    # Feature 8: Dash in domain
    dash_in_domain = 1 if '-' in hostname else 0

    # Feature 9: Suspicious TLD
    suspicious_tld = 1 if ext.suffix.lower() in SUSPICIOUS_TLDS else 0

    # Feature 10: URL Shortener
    is_shortener = 1 if (registered_domain.lower() in SHORTENER_DOMAINS or hostname.lower() in SHORTENER_DOMAINS) else 0

    # Feature 11: Sensitive keywords count
    matched_keywords = [kw for kw in SENSITIVE_KEYWORDS if kw in full_url.lower()]
    sensitive_keywords_count = len(matched_keywords)

    # Feature 12: HTTPS in domain
    https_in_domain = 1 if 'https' in hostname.lower() else 0

    # Feature 13: Is HTTPS scheme
    is_https = 1 if parsed.scheme == 'https' else 0

    # Feature 14: Digit ratio
    digits_count = sum(c.isdigit() for c in full_url)
    digit_ratio = round(digits_count / max(len(full_url), 1), 4)

    # Feature 15: Special char count
    special_chars = sum(full_url.count(c) for c in ['?', '=', '%', '-', '_', '&', '~', '#', '+', '$'])

    # Feature 16: Homoglyph / Punycode
    homoglyph = check_homoglyph_or_punycode(hostname)

    # Feature 17: Path depth
    path_depth = len([p for p in parsed.path.split('/') if p])

    # Feature 18: Query param count
    query_param_count = len(urllib.parse.parse_qs(parsed.query))

    # Feature 19: Brand impersonation score
    impersonation_score, detected_brand = detect_brand_impersonation(full_url, registered_domain)

    # Feature 20: Hex encoding present
    hex_encoding = 1 if re.search(r'%[0-9a-fA-F]{2}', full_url) else 0

    # Feature 21: Non standard port
    has_custom_port = 1 if parsed.port and parsed.port not in (80, 443) else 0

    # Feature 22: Consecutive dots
    consecutive_dots = 1 if '..' in full_url else 0

    features_dict = {
        'url_length': url_length,
        'domain_length': domain_length,
        'subdomain_count': subdomain_count,
        'has_ip': has_ip,
        'entropy': entropy,
        'has_at_symbol': has_at_symbol,
        'has_double_slash': has_double_slash,
        'dash_in_domain': dash_in_domain,
        'suspicious_tld': suspicious_tld,
        'url_shortener': is_shortener,
        'sensitive_keywords_count': sensitive_keywords_count,
        'https_in_domain': https_in_domain,
        'is_https': is_https,
        'digit_ratio': digit_ratio,
        'special_char_count': special_chars,
        'homoglyph': homoglyph,
        'path_depth': path_depth,
        'query_param_count': query_param_count,
        'brand_impersonation': impersonation_score,
        'hex_encoding': hex_encoding,
        'has_custom_port': has_custom_port,
        'consecutive_dots': consecutive_dots
    }

    metadata = {
        'raw_url': url_string,
        'scheme': parsed.scheme or 'http',
        'hostname': hostname,
        'domain': registered_domain,
        'subdomains': subdomains,
        'tld': ext.suffix,
        'path': parsed.path,
        'query': parsed.query,
        'matched_keywords': matched_keywords,
        'detected_brand': detected_brand
    }

    return features_dict, metadata

def perform_live_checks(url_string):
    """
    Performs optional live DNS, SSL, and HTTP handshake checks safely with timeout.
    """
    features, meta = extract_url_features(url_string)
    hostname = meta['hostname']
    
    live_status = {
        'dns_resolvable': False,
        'resolved_ips': [],
        'ssl_valid': False,
        'ssl_issuer': None,
        'ssl_days_remaining': None,
        'http_status': None,
        'has_hsts': False,
        'server_header': None
    }

    if not hostname:
        return live_status

    # 1. DNS Check
    try:
        ip_list = socket.gethostbyname_ex(hostname)[2]
        live_status['dns_resolvable'] = True
        live_status['resolved_ips'] = ip_list
    except Exception:
        live_status['dns_resolvable'] = False

    # 2. SSL Check
    if meta['scheme'] == 'https' or live_status['dns_resolvable']:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=1.5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    live_status['ssl_valid'] = True
                    # Extract issuer
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    live_status['ssl_issuer'] = issuer.get('organizationName') or issuer.get('commonName')
                    # Calculate remaining days
                    not_after = cert.get('notAfter')
                    if not_after:
                        expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expire_date - datetime.utcnow()).days
                        live_status['ssl_days_remaining'] = days_left
        except Exception:
            live_status['ssl_valid'] = False

    # 3. HTTP Live Request Check
    try:
        target_url = url_string if url_string.startswith(('http://', 'https://')) else 'http://' + url_string
        resp = requests.head(target_url, timeout=1.5, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0 (Security Scanner)'})
        live_status['http_status'] = resp.status_code
        live_status['has_hsts'] = 'Strict-Transport-Security' in resp.headers
        live_status['server_header'] = resp.headers.get('Server')
    except Exception:
        # Fallback GET if HEAD rejected
        try:
            resp = requests.get(target_url, timeout=1.5, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0 (Security Scanner)'}, stream=True)
            live_status['http_status'] = resp.status_code
            live_status['has_hsts'] = 'Strict-Transport-Security' in resp.headers
            live_status['server_header'] = resp.headers.get('Server')
        except Exception:
            pass

    return live_status
