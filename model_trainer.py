import os
import random
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import joblib

from feature_extractor import extract_url_features, SENSITIVE_KEYWORDS, SUSPICIOUS_TLDS, SHORTENER_DOMAINS

# Base directory setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
MODELS_DIR = os.path.join(BASE_DIR, 'models')

os.makedirs(DATASET_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

LEGITIMATE_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'wikipedia.org', 'amazon.com',
    'microsoft.com', 'apple.com', 'netflix.com', 'reddit.com', 'twitter.com',
    'linkedin.com', 'instagram.com', 'github.com', 'stackoverflow.com', 'chase.com',
    'wellsfargo.com', 'bankofamerica.com', 'paypal.com', 'binance.com', 'coinbase.com',
    'nytimes.com', 'bbc.com', 'cnn.com', 'medium.com', 'adobe.com', 'dropbox.com',
    'spotify.com', 'zoom.us', 'slack.com', 'canva.com', 'shopify.com', 'salesforce.com',
    'notion.so', 'figma.com', 'cloudflare.com', 'gitlab.com', 'hubspot.com'
]

LEGITIMATE_PATHS = [
    '', '/', '/search?q=security', '/help/center/article?id=102',
    '/products/category/electronics', '/user/profile', '/docs/v2/api-overview',
    '/about-us', '/contact', '/blog/2026/cybersecurity-best-practices',
    '/pricing', '/download/desktop-app', '/resources/whitepaper.pdf'
]

PHISHING_PATTERNS = [
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
    
    # IP Address Hostnames
    ('http://192.168.1.105/paypal/login.php?user=verify', 1),
    ('http://45.33.22.11/secure/bankofamerica/signin', 1),
    ('http://185.220.101.5/apple/id/auth', 1),
    ('http://104.28.19.44/google-drive/share-document', 1),

    # URL Shorteners hiding phishing targets
    ('http://bit.ly/3xX9PzL_paypal_verify', 1),
    ('http://tinyurl.com/y8z9w2kq_bank_update', 1),
    ('http://cutt.ly/claim-crypto-reward-now', 1),

    # Obfuscation & Sensitive Keywords
    ('http://secure-update-verify-banking-account-login.com.search-gateway.tk/auth.php', 1),
    ('http://customer-support-helpdesk-credential-validation.work/reset-password', 1),
    ('http://verify.account-update.bank.gq/login?id=84920492', 1),
    ('http://login.account-check.site/paypal/?cmd=_login-run&dispatch=5885d80a13c0db1f8e263663d3faee8d', 1)
]

def generate_synthetic_dataset(num_samples=4000):
    """
    Generates a balanced, realistic dataset of URLs with standard features labeled 0 (legit) and 1 (phishing).
    """
    urls = []
    labels = []

    # Add hand-crafted phishing patterns
    for url, label in PHISHING_PATTERNS:
        urls.append(url)
        labels.append(label)

    # Generate Legitimate Samples (~50%)
    for _ in range(num_samples // 2):
        domain = random.choice(LEGITIMATE_DOMAINS)
        subdomain = random.choice(['', '', '', 'www.', 'app.', 'docs.', 'auth.', 'blog.', 'support.'])
        path = random.choice(LEGITIMATE_PATHS)
        scheme = random.choice(['https://', 'https://', 'https://', 'http://'])
        
        full_url = f"{scheme}{subdomain}{domain}{path}"
        urls.append(full_url)
        labels.append(0)

    # Generate Phishing Samples (~50%)
    brands = ['paypal', 'google', 'apple', 'microsoft', 'amazon', 'netflix', 'chase', 'binance', 'coinbase']
    tlds = list(SUSPICIOUS_TLDS) + ['com', 'org', 'info', 'net']
    shorteners = list(SHORTENER_DOMAINS)
    keywords = SENSITIVE_KEYWORDS

    for _ in range(num_samples // 2 - len(PHISHING_PATTERNS)):
        strategy = random.choice(['typosquat', 'ip_host', 'subdomain_stack', 'shortener', 'keyword_stuffing'])
        scheme = random.choice(['http://', 'http://', 'https://'])

        if strategy == 'typosquat':
            brand = random.choice(brands)
            tld = random.choice(tlds)
            prefix = random.choice(['login-', 'secure-', 'account-', 'verify-', 'update-'])
            domain = f"{prefix}{brand}-service.{tld}"
            path = f"/{random.choice(keywords)}?ref={random.randint(1000, 999999)}"
            url = f"{scheme}{domain}{path}"

        elif strategy == 'ip_host':
            ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            brand = random.choice(brands)
            kw = random.choice(keywords)
            url = f"http://{ip}/{brand}/{kw}.php?token={random.randint(100000, 999999)}"

        elif strategy == 'subdomain_stack':
            brand = random.choice(brands)
            kw1 = random.choice(keywords)
            kw2 = random.choice(keywords)
            tld = random.choice(tlds)
            random_host = f"user-{random.randint(100, 999)}.{tld}"
            url = f"{scheme}{kw1}.{brand}.{kw2}.{random_host}/auth/step2"

        elif strategy == 'shortener':
            shortener = random.choice(shorteners)
            slug = f"{random.choice(brands)}_{random.choice(keywords)}_{random.randint(10, 99)}"
            url = f"http://{shortener}/{slug}"

        else: # keyword stuffing & excessive parameters
            domain = f"sec-{random.randint(100,999)}-gateway.{random.choice(tlds)}"
            kws = random.sample(keywords, 4)
            path = f"/{'/'.join(kws)}/index.html"
            query = f"?user_id={random.randint(10000,99999)}&hash={random.getrandbits(64):x}"
            url = f"{scheme}{domain}{path}{query}"

        urls.append(url)
        labels.append(1)

    df_raw = pd.DataFrame({'url': urls, 'label': labels})
    df_raw.to_csv(os.path.join(DATASET_DIR, 'phishing_urls_dataset.csv'), index=False)
    print(f"[Dataset] Generated {len(df_raw)} total samples saved to dataset/phishing_urls_dataset.csv")
    return df_raw

def train_and_save_model():
    print("[Trainer] Starting dataset feature extraction & model training...")
    df_raw = generate_synthetic_dataset(num_samples=4000)

    features_list = []
    labels_list = []

    for idx, row in df_raw.iterrows():
        url = row['url']
        label = row['label']
        try:
            feats, _ = extract_url_features(url)
            features_list.append(feats)
            labels_list.append(label)
        except Exception as e:
            continue

    df_features = pd.DataFrame(features_list)
    feature_names = list(df_features.columns)

    X = df_features.values
    y = np.array(labels_list)

    # Train test split (80-20)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Standard Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Ensemble Classifier: Random Forest + Gradient Boosting
    rf_clf = RandomForestClassifier(n_estimators=150, max_depth=15, random_state=42, n_jobs=-1)
    gb_clf = GradientBoostingClassifier(n_estimators=120, learning_rate=0.1, max_depth=6, random_state=42)

    ensemble = VotingClassifier(
        estimators=[('rf', rf_clf), ('gb', gb_clf)],
        voting='soft'
    )

    ensemble.fit(X_train_scaled, y_train)

    # Fit RF individually for feature importance extraction
    rf_clf.fit(X_train_scaled, y_train)
    importances = rf_clf.feature_importances_

    # Evaluation
    y_pred = ensemble.predict(X_test_scaled)
    y_proba = ensemble.predict_proba(X_test_scaled)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred))
    rec = float(recall_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    roc_auc = float(roc_auc_score(y_test, y_proba))
    cm = confusion_matrix(y_test, y_pred).tolist()

    print(f"\n================ MODEL EVALUATION METRICS ================")
    print(f"Accuracy:  {acc * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"Recall:    {rec * 100:.2f}%")
    print(f"F1-Score:  {f1 * 100:.2f}%")
    print(f"ROC-AUC:   {roc_auc:.4f}")
    print("=========================================================\n")

    # Format feature importances
    feat_importance_dict = {
        name: float(imp) for name, imp in sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)
    }

    model_package = {
        'model': ensemble,
        'scaler': scaler,
        'feature_names': feature_names,
        'metrics': {
            'accuracy': round(acc, 4),
            'precision': round(prec, 4),
            'recall': round(rec, 4),
            'f1_score': round(f1, 4),
            'roc_auc': round(roc_auc, 4),
            'confusion_matrix': cm
        },
        'feature_importances': feat_importance_dict,
        'trained_at': pd.Timestamp.now().isoformat()
    }

    model_path = os.path.join(MODELS_DIR, 'phishing_model.joblib')
    joblib.dump(model_package, model_path)
    print(f"[Trainer] Model successfully trained and saved to {model_path}")

    return model_package

if __name__ == '__main__':
    train_and_save_model()
