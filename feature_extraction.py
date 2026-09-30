import re
import math
import urllib.parse
import tldextract

# Known URL shorteners
SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'ow.ly', 'buff.ly', 'adf.ly',
    'bit.do', 'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc', 'bc.vc', 'qr.ae',
    'v.gd', 'po.st', 'clck.ru', 's.id'
}

# Suspicious TLDs frequently associated with phishing
SUSPICIOUS_TLDS = {
    'zip', 'mov', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'icu',
    'cn', 'ru', 'cc', 'fit', 'kim', 'rest', 'beauty', 'click', 'link', 'best',
    'online', 'site', 'monster', 'club', 'space', 'website', 'buzz', 'tech'
}

# Sensitive credential and banking keywords
SENSITIVE_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'bank', 'secure', 'update',
    'banking', 'wallet', 'support', 'confirm', 'credential', 'paypal',
    'apple', 'google', 'netflix', 'microsoft', 'meta', 'pay', 'auth',
    'recover', 'security', 'billing', 'password', 'service', 'validation',
    'checkout', 'verification', 'token', 'passcode', 'web3'
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

def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy of string to detect random obfuscation."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    for count in [text.count(c) for c in set(text)]:
        freq = count / length
        entropy -= freq * math.log2(freq)
    return round(entropy, 4)

def is_ip_address(hostname: str) -> int:
    """Detects if hostname is an IPv4 or IPv6 address instead of domain name."""
    if not hostname:
        return 0
    # IPv4 regex
    ipv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    if re.match(ipv4_pattern, hostname):
        return 1
    # Hex or IPv6
    if re.match(r'^0x[0-9a-fA-F]+$', hostname) or ':' in hostname:
        return 1
    return 0

def detect_brand_impersonation(url: str, domain: str):
    """Detects if domain is attempting brand impersonation."""
    url_lower = url.lower()
    domain_lower = domain.lower()
    
    for brand, official_domains in TARGET_BRANDS.items():
        if brand in url_lower:
            is_official = any(official in domain_lower for official in official_domains)
            if not is_official:
                return 1.0, brand
    return 0.0, None

def extract_url_features(url_string: str):
    """
    Extracts comprehensive lexical and structural features from a URL.
    Returns:
        tuple: (features_dict, metadata_dict)
    """
    url = url_string.strip()
    if not url.startswith(('http://', 'https://')):
        full_url = 'http://' + url
    else:
        full_url = url

    parsed = urllib.parse.urlparse(full_url)
    ext = tldextract.extract(full_url)

    hostname = parsed.netloc.split(':')[0] if parsed.netloc else ''
    registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    subdomains = ext.subdomain

    # 1. URL Length
    url_length = len(full_url)

    # 2. Domain Length
    domain_length = len(registered_domain)

    # 3. Subdomain count & Number of dots
    subdomain_count = len(subdomains.split('.')) if subdomains else 0
    dot_count = full_url.count('.')

    # 4. Having IP address instead of domain name
    has_ip = is_ip_address(hostname)

    # 5. Shannon Entropy
    entropy = calculate_shannon_entropy(full_url)

    # 6. Presence of '@' symbol
    has_at_symbol = 1 if '@' in full_url else 0

    # 7. Presence of redirection '//' (excluding protocol double slash)
    path_and_query = parsed.path + ('?' + parsed.query if parsed.query else '')
    has_double_slash = 1 if '//' in path_and_query else 0

    # 8. Prefix/Suffix separated by '-' in domain
    dash_in_domain = 1 if '-' in hostname else 0

    # 9. Suspicious TLD
    suspicious_tld = 1 if ext.suffix.lower() in SUSPICIOUS_TLDS else 0

    # 10. Use of URL shortening services
    is_shortener = 1 if (registered_domain.lower() in SHORTENER_DOMAINS or hostname.lower() in SHORTENER_DOMAINS) else 0

    # 11. Count of sensitive keywords
    matched_keywords = [kw for kw in SENSITIVE_KEYWORDS if kw in full_url.lower()]
    sensitive_keywords_count = len(matched_keywords)

    # 12. HTTPS token presence in domain portion (e.g., http://https-paypal-security.com)
    https_in_domain = 1 if 'https' in hostname.lower() else 0

    # 13. Scheme is HTTPS
    is_https = 1 if parsed.scheme.lower() == 'https' else 0

    # 14. Digit ratio in URL
    digits_count = sum(c.isdigit() for c in full_url)
    digit_ratio = round(digits_count / max(len(full_url), 1), 4)

    # 15. Special characters count
    special_chars = sum(full_url.count(c) for c in ['?', '=', '%', '-', '_', '&', '~', '#', '+', '$'])

    # 16. Homoglyph / Punycode
    homoglyph = 1 if 'xn--' in hostname else 0

    # 17. Path depth
    path_depth = len([p for p in parsed.path.split('/') if p])

    # 18. Query param count
    query_param_count = len(urllib.parse.parse_qs(parsed.query))

    # 19. Brand impersonation score
    impersonation_score, detected_brand = detect_brand_impersonation(full_url, registered_domain)

    # 20. Hex encoding present
    hex_encoding = 1 if re.search(r'%[0-9a-fA-F]{2}', full_url) else 0

    features_dict = {
        'url_length': url_length,
        'domain_length': domain_length,
        'subdomain_count': subdomain_count,
        'dot_count': dot_count,
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
        'hex_encoding': hex_encoding
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

def extract_features(url_string: str):
    """Convenience helper returning only the features dictionary."""
    features_dict, _ = extract_url_features(url_string)
    return features_dict
