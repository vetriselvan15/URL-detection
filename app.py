import os
import time
import joblib
import numpy as np
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS

from feature_extraction import extract_url_features, SENSITIVE_KEYWORDS, SUSPICIOUS_TLDS

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')
MODEL_PKL_PATH = os.path.join(BASE_DIR, 'model.pkl')
MODEL_JOBLIB_PATH = os.path.join(BASE_DIR, 'models', 'phishing_model.joblib')

app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
CORS(app)

def get_loaded_model():
    """Loads trained model.pkl or models/phishing_model.joblib; triggers training if missing."""
    if os.path.exists(MODEL_PKL_PATH):
        print(f"[App] Loading model package from '{MODEL_PKL_PATH}'...")
        return joblib.load(MODEL_PKL_PATH)
    elif os.path.exists(MODEL_JOBLIB_PATH):
        print(f"[App] Loading model package from '{MODEL_JOBLIB_PATH}'...")
        return joblib.load(MODEL_JOBLIB_PATH)
    else:
        print("[App] Model file not found. Executing train.py to build model package...")
        from train import train_ensemble_model
        return train_ensemble_model()

model_package = get_loaded_model()
model = model_package['model']
scaler = model_package['scaler']
feature_names = model_package['feature_names']
model_metrics = model_package['metrics']
feature_importances = model_package['feature_importances']

print("[App] Phishing URL Detection Flask server initialized successfully.")

@app.route('/')
def index():
    return render_template('index.html', metrics=model_metrics)

@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    return jsonify({
        'metrics': model_metrics,
        'feature_importances': feature_importances
    })

def analyze_url(raw_url):
    """Core analysis logic for a single URL."""
    start_time = time.time()

    # 1. Feature Extraction
    features_dict, metadata = extract_url_features(raw_url)

    # 2. Machine Learning Prediction
    feature_vector = np.array([[features_dict[name] for name in feature_names]])
    scaled_vector = scaler.transform(feature_vector)

    # Predict probability of phishing class (1)
    phishing_prob = float(model.predict_proba(scaled_vector)[0][1])
    legit_prob = 1.0 - phishing_prob
    
    # Prediction label
    is_phishing = phishing_prob >= 0.50

    # 3. Rule-based Heuristic Enhancements (Fail-safe checks)
    heuristic_flags = []

    if features_dict['has_ip']:
        heuristic_flags.append("Direct IP address used instead of valid registered domain name.")
        phishing_prob = max(phishing_prob, 0.85)

    if features_dict['has_at_symbol']:
        heuristic_flags.append("Contains '@' symbol which tricks URL parser into ignoring prefix.")
        phishing_prob = max(phishing_prob, 0.80)

    if features_dict['has_double_slash']:
        heuristic_flags.append("Contains '//' double slash redirection in path.")
        phishing_prob = max(phishing_prob, 0.75)

    if features_dict['url_shortener']:
        heuristic_flags.append("Known URL shortener service used to obfuscate destination.")

    if features_dict['https_in_domain']:
        heuristic_flags.append("Domain name contains deceptive 'https' token.")
        phishing_prob = max(phishing_prob, 0.85)

    if features_dict['sensitive_keywords_count'] >= 2:
        matched_str = ", ".join(metadata['matched_keywords'])
        heuristic_flags.append(f"Contains multiple sensitive keywords: {matched_str}")

    if metadata['detected_brand']:
        heuristic_flags.append(f"Impersonating official brand '{metadata['detected_brand'].upper()}' on third-party domain.")
        phishing_prob = max(phishing_prob, 0.92)

    if features_dict['suspicious_tld']:
        heuristic_flags.append(f"Domain uses high-risk suspicious TLD (.{metadata['tld']}).")

    confidence = round(phishing_prob * 100 if is_phishing else legit_prob * 100, 1)

    # Verdict Badge Classification
    if phishing_prob >= 0.50:
        verdict = "Phishing Alert"
        verdict_badge = "danger"
        verdict_status = "phishing"
    else:
        verdict = "Safe / Legitimate"
        verdict_badge = "success"
        verdict_status = "legitimate"

    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    return {
        'url': raw_url,
        'verdict': verdict,
        'verdict_status': verdict_status,
        'verdict_badge': verdict_badge,
        'confidence': confidence,
        'phishing_probability': round(phishing_prob * 100, 2),
        'legitimate_probability': round(legit_prob * 100, 2),
        'heuristic_flags': heuristic_flags,
        'features': features_dict,
        'metadata': metadata,
        'scan_time_ms': elapsed_ms
    }

@app.route('/api/scan', methods=['POST'])
def scan_url():
    data = request.json or request.form or {}
    raw_url = data.get('url', '').strip()

    if not raw_url:
        return jsonify({'error': 'Please enter a valid URL to analyze.'}), 400

    result = analyze_url(raw_url)
    return jsonify(result)

@app.route('/api/scan-batch', methods=['POST'])
def scan_batch():
    urls = []
    
    # Handle CSV file upload
    if 'file' in request.files:
        file = request.files['file']
        if file and file.filename.endswith('.csv'):
            try:
                import pandas as pd
                df = pd.read_csv(file)
                # Find URL column (url, URL, link, domain)
                col = next((c for c in df.columns if c.lower() in ['url', 'urls', 'link', 'domain']), df.columns[0])
                urls = [str(x).strip() for x in df[col].dropna() if str(x).strip()]
            except Exception as e:
                return jsonify({'error': f'Failed to process CSV file: {str(e)}'}), 400

    # Handle JSON payload list of URLs or newline text string
    if not urls and request.is_json:
        data = request.get_json()
        if isinstance(data.get('urls'), list):
            urls = [str(u).strip() for u in data['urls'] if str(u).strip()]
        elif isinstance(data.get('urls_text'), str):
            urls = [line.strip() for line in data['urls_text'].split('\n') if line.strip()]

    if not urls:
        return jsonify({'error': 'No valid URLs provided for batch scanning.'}), 400

    # Cap batch scanning at 500 URLs per request for performance
    urls = urls[:500]
    
    results = []
    phishing_count = 0
    legitimate_count = 0

    for u in urls:
        res = analyze_url(u)
        if res['verdict_status'] == 'phishing':
            phishing_count += 1
        else:
            legitimate_count += 1
        results.append(res)

    return jsonify({
        'total_scanned': len(results),
        'phishing_count': phishing_count,
        'legitimate_count': legitimate_count,
        'results': results
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
