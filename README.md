# 🛡️ PhishGuard AI: Intelligent Phishing URL Detection System

An enterprise-grade, machine-learning-powered cybersecurity tool designed to detect phishing and malicious URLs in real time. Built with an **Ensemble Soft Voting Classifier (Random Forest + Gradient Boosting / XGBoost)** and a **Rule-Based Heuristic Safety Engine**, PhishGuard AI achieves over **99.88% accuracy** in detecting sophisticated phishing techniques.

---

## 🌟 Key Features

* **⚡ Real-Time Single & Batch URL Scanning**: Analyze individual links or upload a `.csv` file containing hundreds of URLs for bulk analysis.
* **🤖 Ensemble Machine Learning Architecture**: Combines tuned **Random Forest** and **Gradient Boosting / XGBoost** classifiers with 5-Fold Stratified Cross-Validation.
* **🔬 21 Lexical & Structural Features**:
  * **Entropy & Randomness**: Shannon entropy calculations to detect domain obfuscation.
  * **Brand Impersonation Engine**: Identifies spoofing of popular services (PayPal, Google, Apple, Microsoft, Amazon, Bank of America, Netflix, Steam, etc.).
  * **Structural Anomalies**: IP hostname usage, `@` prefix tricks, double-slash redirection, suspicious TLDs (`.xyz`, `.top`, `.cc`, etc.), sensitive keyword matching, and URL length ratio.
* **🛡️ Rule-Based Heuristic Fail-Safe Engine**: Ensures zero bypasses for dangerous edge cases (e.g., direct IP hosting, homoglyphs, brand spoofing on third-party domains).
* **📊 Modern Glassmorphism Dashboard**: Dark-mode UI built with Flask, CSS glassmorphism, Font Awesome icons, real-time confidence scores, interactive metrics, and downloadable CSV report export.

---

## 📐 Machine Learning Performance Metrics

| Metric | Score | Benchmark Target |
| :--- | :--- | :--- |
| **5-Fold CV Accuracy (Random Forest)** | **99.97%** | `> 90.00%` |
| **5-Fold CV Accuracy (Gradient Boosting)** | **99.91%** | `> 90.00%` |
| **Test Dataset Accuracy** | **99.88%** | `> 90.00%` |
| **Precision** | **100.00%** | `> 90.00%` |
| **Recall** | **99.75%** | `> 90.00%` |
| **F1-Score** | **99.87%** | `> 90.00%` |

---

## 🛠️ Project Structure

```
phishing-url-detection-system/
├── app.py                     # Flask web server & REST API endpoints (/api/scan, /api/scan-batch)
├── feature_extraction.py      # Feature engineering module (21 lexical/structural features)
├── dataset_generator.py       # Synthetic dataset generator fallback engine
├── train.py                   # Model training, hyperparameter grid search, CV & model packaging
├── requirements.txt           # Python dependencies
├── model.pkl                  # Serialized trained model package (Ensemble + Scaler + Feature metadata)
├── models/
│   └── phishing_model.joblib  # Backup model joblib binary
├── dataset/
│   └── phishing_urls_dataset.csv # 4000+ sample training dataset (50% Phishing, 50% Legitimate)
├── templates/
│   └── index.html             # Single & Batch URL scan web dashboard UI
└── README.md                  # Project documentation
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
* Python **3.8+**
* `pip` package manager

### 2. Installation
Clone or navigate to the project directory and install the required dependencies:
```bash
pip install -r requirements.txt
```

### 3. (Optional) Re-Train Machine Learning Model
To run 5-Fold Stratified Cross-Validation, perform GridSearch hyperparameter tuning, and export a fresh `model.pkl`:
```bash
python train.py
```

### 4. Launch the Web Application
Start the Flask web server:
```bash
python app.py
```
Open your web browser and navigate to:
👉 **`http://localhost:5000`**

---

## 📡 API Endpoints

### 1. Single URL Analysis
* **Endpoint**: `POST /api/scan`
* **Headers**: `Content-Type: application/json`
* **Body**:
```json
{
  "url": "http://paypal-security-update.com-login.net"
}
```
* **Sample Response**:
```json
{
  "confidence": 92.0,
  "phishing_probability": 92.0,
  "legitimate_probability": 8.0,
  "verdict": "Phishing Alert",
  "verdict_status": "phishing",
  "heuristic_flags": [
    "Contains multiple sensitive keywords: login, update, paypal, pay, security",
    "Impersonating official brand 'PAYPAL' on third-party domain."
  ],
  "features": {
    "url_length": 43,
    "has_ip": 0,
    "brand_impersonation": 1.0,
    "entropy": 4.22
  }
}
```

### 2. Batch URL Analysis
* **Endpoint**: `POST /api/scan-batch`
* **Form Upload**: CSV file attached as `file` parameter, OR JSON payload with `{"urls": ["http://...", "http://..."]}`.
* **Sample Response**: Returns summary metrics (`total_scanned`, `phishing_count`, `legitimate_count`) and array of per-URL verdicts.

---

## 🧪 Example Test URLs

| Category | Example URL | Expected Verdict |
| :--- | :--- | :--- |
| **Legitimate Search Engine** | `https://www.google.com` | ✅ Safe / Legitimate |
| **Legitimate Code Repository** | `https://github.com/login` | ✅ Safe / Legitimate |
| **IP-Based Phishing** | `http://192.168.1.50/account/login.php` | 🚨 Phishing Alert |
| **Brand Impersonation** | `http://paypaI-security-update.account-verify.xyz/login.html` | 🚨 Phishing Alert |
| **Deceptive `@` Symbol Trick** | `http://google.com@login-verify-pass.com/auth` | 🚨 Phishing Alert |

---

## 📄 License
This project is open-source under the MIT License. Developed for cybersecurity research and education.
