import os
import random
import pandas as pd
from feature_extraction import SENSITIVE_KEYWORDS, SUSPICIOUS_TLDS, SHORTENER_DOMAINS

LEGITIMATE_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'wikipedia.org', 'amazon.com',
    'microsoft.com', 'apple.com', 'netflix.com', 'reddit.com', 'twitter.com',
    'linkedin.com', 'instagram.com', 'github.com', 'stackoverflow.com', 'chase.com',
    'wellsfargo.com', 'bankofamerica.com', 'paypal.com', 'binance.com', 'coinbase.com',
    'nytimes.com', 'bbc.com', 'cnn.com', 'medium.com', 'adobe.com', 'dropbox.com',
    'spotify.com', 'zoom.us', 'slack.com', 'canva.com', 'shopify.com', 'salesforce.com',
    'notion.so', 'figma.com', 'cloudflare.com', 'gitlab.com', 'hubspot.com', 'walmart.com',
    'ebay.com', 'target.com', 'etsy.com', 'quora.com', 'espn.com', 'imdb.com'
]

LEGITIMATE_PATHS = [
    '', '/', '/search?q=security', '/help/center/article?id=102',
    '/products/category/electronics', '/user/profile', '/docs/v2/api-overview',
    '/about-us', '/contact', '/blog/2026/cybersecurity-best-practices',
    '/pricing', '/download/desktop-app', '/resources/whitepaper.pdf',
    '/dashboard/main', '/settings/privacy', '/account/manage', '/login'
]

REAL_WORLD_PHISHING_SAMPLES = [
    # Typosquatting & Brand Impersonation
    ('http://paypaI-security-update.account-verify.xyz/login.html', 1),
    ('http://login.paypal.com.user-auth-check.top/verify', 1),
    ('http://accounts.googIe.com-signin-security.info/auth', 1),
    ('http://appIe-id.account-recovery-service.online/restore', 1),
    ('http://microsoft-online-vault.auth-update.site/login', 1),
    ('http://chasebank-online-security.verify-credentials.xyz/signin', 1),
    ('http://binance-wallet-connect.web3-claim-airdrop.top/vault', 1),
    ('http://metamask-io-claim-bonus.crypto-reward.click/seed', 1),
    ('http://wellsfargo-banking-alert.secure-client.buzz/update', 1),
    ('http://netflix-billing-issue.account-reactivate.rest/payment', 1),
    ('http://https-paypal-login-account-update.xyz/verify', 1),
    ('http://amazon-prime-reward.winner-claim2026.online/claim', 1),
    
    # IP Address Hostnames
    ('http://192.168.1.105/paypal/login.php?user=verify', 1),
    ('http://45.33.22.11/secure/bankofamerica/signin', 1),
    ('http://185.220.101.5/apple/id/auth', 1),
    ('http://104.28.19.44/google-drive/share-document', 1),
    ('http://192.241.170.12/verify/account/banking', 1),

    # URL Shorteners hiding phishing targets
    ('http://bit.ly/3xX9PzL_paypal_verify', 1),
    ('http://tinyurl.com/y8z9w2kq_bank_update', 1),
    ('http://cutt.ly/claim-crypto-reward-now', 1),
    ('http://is.gd/secure_login_token', 1),

    # Obfuscation, Special Chars, Sensitive Keywords & Redirections
    ('http://secure-update-verify-banking-account-login.com.search-gateway.tk/auth.php', 1),
    ('http://customer-support-helpdesk-credential-validation.work/reset-password', 1),
    ('http://verify.account-update.bank.gq/login?id=84920492', 1),
    ('http://login.account-check.site/paypal/?cmd=_login-run&dispatch=5885d80a13c0db1f8e263663d3faee8d', 1),
    ('http://user@malicious-phish-domain.com/login', 1),
    ('http://trusted-site.com//redirect-to-phish-vault.xyz/login', 1)
]

def generate_dataset(num_samples=5000, output_file='dataset.csv'):
    """Generates a realistic synthetic CSV dataset for training Phishing URL models."""
    urls = []
    labels = []

    # 1. Add curated phishing samples
    for url, label in REAL_WORLD_PHISHING_SAMPLES:
        urls.append(url)
        labels.append(label)

    # 2. Add real-world legitimate URLs
    for domain in LEGITIMATE_DOMAINS:
        urls.append(f"https://{domain}/")
        labels.append(0)
        urls.append(f"https://www.{domain}/login")
        labels.append(0)
        urls.append(f"https://{domain}/account/settings")
        labels.append(0)

    half_samples = (num_samples - len(urls)) // 2

    # 3. Generate Legitimate URLs (~50%)
    for _ in range(half_samples):
        domain = random.choice(LEGITIMATE_DOMAINS)
        subdomain = random.choice(['', '', '', 'www.', 'app.', 'docs.', 'auth.', 'blog.', 'support.'])
        path = random.choice(LEGITIMATE_PATHS)
        scheme = random.choice(['https://', 'https://', 'https://', 'http://'])
        
        full_url = f"{scheme}{subdomain}{domain}{path}"
        urls.append(full_url)
        labels.append(0)

    # 4. Generate Synthetic Phishing URLs (~50%)
    brands = ['paypal', 'google', 'apple', 'microsoft', 'amazon', 'netflix', 'chase', 'binance', 'coinbase', 'wellsfargo']
    tlds = list(SUSPICIOUS_TLDS) + ['com', 'org', 'info', 'net', 'online', 'site', 'xyz']
    shorteners = list(SHORTENER_DOMAINS)

    while len(urls) < num_samples:
        strategy = random.choice([
            'typosquat', 'ip_host', 'subdomain_stack', 'shortener', 
            'keyword_stuffing', 'at_symbol', 'https_in_domain', 'double_slash'
        ])
        scheme = random.choice(['http://', 'http://', 'https://'])

        if strategy == 'typosquat':
            brand = random.choice(brands)
            tld = random.choice(tlds)
            prefix = random.choice(['login-', 'secure-', 'account-', 'verify-', 'update-'])
            domain = f"{prefix}{brand}-service.{tld}"
            path = f"/{random.choice(SENSITIVE_KEYWORDS)}?ref={random.randint(1000, 999999)}"
            url = f"{scheme}{domain}{path}"

        elif strategy == 'ip_host':
            ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            brand = random.choice(brands)
            kw = random.choice(SENSITIVE_KEYWORDS)
            url = f"http://{ip}/{brand}/{kw}.php?token={random.randint(100000, 999999)}"

        elif strategy == 'subdomain_stack':
            brand = random.choice(brands)
            kw1 = random.choice(SENSITIVE_KEYWORDS)
            kw2 = random.choice(SENSITIVE_KEYWORDS)
            tld = random.choice(tlds)
            url = f"{scheme}{kw1}.{kw2}.{brand}.auth-gateway.{tld}/signin"

        elif strategy == 'shortener':
            shortener = random.choice(shorteners)
            code = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=7))
            url = f"http://{shortener}/{code}_verify_account"

        elif strategy == 'at_symbol':
            brand = random.choice(brands)
            tld = random.choice(tlds)
            url = f"http://{brand}.com-security@{random.choice(['phish-host.com', 'secure-vault.xyz'])}/login"

        elif strategy == 'https_in_domain':
            brand = random.choice(brands)
            tld = random.choice(tlds)
            url = f"http://https-{brand}-verification-login.{tld}/update"

        elif strategy == 'double_slash':
            brand = random.choice(brands)
            tld = random.choice(tlds)
            url = f"http://legit-redirect.org//phish-site.{tld}/auth"

        else:  # keyword_stuffing
            kws = random.sample(SENSITIVE_KEYWORDS, k=3)
            tld = random.choice(tlds)
            url = f"{scheme}{'-'.join(kws)}.{tld}/verify.php"

        urls.append(url)
        labels.append(1)

    df = pd.DataFrame({'url': urls, 'label': labels})
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(output_file, index=False)
    print(f"[Dataset] Created dataset with {len(df)} samples at '{output_file}'. Label distribution:\n{df['label'].value_counts()}")
    return df

if __name__ == '__main__':
    generate_dataset()
