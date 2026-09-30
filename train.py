import os
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report

from feature_extraction import extract_url_features
from dataset_generator import generate_dataset

# Try importing XGBoost, fallback to GradientBoostingClassifier if unavailable
try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_FILE = os.path.join(BASE_DIR, 'dataset.csv')
ALT_DATASET_FILE = os.path.join(BASE_DIR, 'dataset', 'phishing_urls_dataset.csv')
MODEL_PKL = os.path.join(BASE_DIR, 'model.pkl')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
MODEL_JOBLIB = os.path.join(MODELS_DIR, 'phishing_model.joblib')

def load_or_create_dataset():
    """Loads dataset CSV if present; otherwise creates dataset.csv using dataset_generator."""
    if os.path.exists(DATASET_FILE):
        print(f"[Dataset] Loading existing dataset from '{DATASET_FILE}'...")
        df = pd.read_csv(DATASET_FILE)
    elif os.path.exists(ALT_DATASET_FILE):
        print(f"[Dataset] Loading existing dataset from '{ALT_DATASET_FILE}'...")
        df = pd.read_csv(ALT_DATASET_FILE)
    else:
        print("[Dataset] Dataset CSV not found. Generating synthetic fallback dataset...")
        df = generate_dataset(num_samples=5000, output_file=DATASET_FILE)
    
    return df

def prepare_feature_matrix(df):
    """Extracts lexical and structural URL features for each URL in DataFrame."""
    print("[Feature Engineering] Extracting lexical and structural URL features...")
    feature_rows = []
    
    for idx, row in df.iterrows():
        url = str(row['url'])
        features, _ = extract_url_features(url)
        feature_rows.append(features)
    
    X_df = pd.DataFrame(feature_rows)
    y = df['label'].values
    return X_df, y

def train_ensemble_model():
    """Trains an Ensemble Classifier (Random Forest + XGBoost/Gradient Boosting) with tuning and CV."""
    os.makedirs(MODELS_DIR, exist_ok=True)
    df = load_or_create_dataset()
    X_df, y = prepare_feature_matrix(df)
    feature_names = list(X_df.columns)

    print(f"[Dataset Summary] Total samples: {len(X_df)}, Features extracted: {len(feature_names)}")

    # Stratified Train-Test Split (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(
        X_df, y, test_size=0.20, random_state=42, stratify=y
    )

    # Standard Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("\n" + "="*60)
    print("      HYPERPARAMETER TUNING & ENSEMBLE CLASSIFIER TRAINING      ")
    print("="*60)

    # 1. Random Forest Classifier & GridSearch
    rf_base = RandomForestClassifier(random_state=42)
    rf_param_grid = {
        'n_estimators': [100, 150],
        'max_depth': [12, 18, None],
        'min_samples_split': [2, 5]
    }
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    rf_grid = GridSearchCV(rf_base, rf_param_grid, cv=skf, scoring='accuracy', n_jobs=-1)
    rf_grid.fit(X_train_scaled, y_train)
    best_rf = rf_grid.best_estimator_
    print(f"[Random Forest] Best Parameters: {rf_grid.best_params_}")
    print(f"[Random Forest] Best 5-Fold CV Accuracy: {rf_grid.best_score_ * 100:.2f}%")

    # 2. XGBoost or Gradient Boosting Classifier & GridSearch
    if HAS_XGBOOST:
        print("\n[XGBoost] Training XGBoost Classifier...")
        xgb_base = XGBClassifier(random_state=42, eval_metric='logloss', use_label_encoder=False)
        xgb_param_grid = {
            'n_estimators': [100, 150],
            'max_depth': [4, 6],
            'learning_rate': [0.05, 0.1]
        }
        xgb_grid = GridSearchCV(xgb_base, xgb_param_grid, cv=skf, scoring='accuracy', n_jobs=-1)
        xgb_grid.fit(X_train_scaled, y_train)
        best_boosting = xgb_grid.best_estimator_
        print(f"[XGBoost] Best Parameters: {xgb_grid.best_params_}")
        print(f"[XGBoost] Best 5-Fold CV Accuracy: {xgb_grid.best_score_ * 100:.2f}%")
        boosting_name = 'XGBoost'
    else:
        print("\n[Gradient Boosting] Training sklearn GradientBoostingClassifier...")
        gb_base = GradientBoostingClassifier(random_state=42)
        gb_param_grid = {
            'n_estimators': [100, 150],
            'max_depth': [4, 6],
            'learning_rate': [0.05, 0.1]
        }
        gb_grid = GridSearchCV(gb_base, gb_param_grid, cv=skf, scoring='accuracy', n_jobs=-1)
        gb_grid.fit(X_train_scaled, y_train)
        best_boosting = gb_grid.best_estimator_
        print(f"[Gradient Boosting] Best Parameters: {gb_grid.best_params_}")
        print(f"[Gradient Boosting] Best 5-Fold CV Accuracy: {gb_grid.best_score_ * 100:.2f}%")
        boosting_name = 'GradientBoosting'

    # 3. Soft Voting Ensemble Classifier (RF + XGBoost/GB)
    ensemble = VotingClassifier(
        estimators=[
            ('rf', best_rf),
            ('boosting', best_boosting)
        ],
        voting='soft'
    )
    ensemble.fit(X_train_scaled, y_train)

    # Evaluate on Test set
    y_pred = ensemble.predict(X_test_scaled)
    y_proba = ensemble.predict_proba(X_test_scaled)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "="*60)
    print("                    EVALUATION METRICS                   ")
    print("="*60)
    print(f" Test Accuracy  : {acc * 100:.2f}%  (Target: 90.00% - 100.00%)")
    print(f" Precision      : {prec * 100:.2f}%")
    print(f" Recall         : {rec * 100:.2f}%")
    print(f" F1-Score       : {f1 * 100:.2f}%")
    print("\nConfusion Matrix:")
    print("                 Predicted Legitimate (0)  Predicted Phishing (1)")
    print(f"Actual Legitimate (0)     {cm[0][0]:<23} {cm[0][1]}")
    print(f"Actual Phishing   (1)     {cm[1][0]:<23} {cm[1][1]}")

    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

    # Feature Importance analysis (using Random Forest)
    importances = dict(zip(feature_names, best_rf.feature_importances_))
    sorted_importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))

    model_package = {
        'model': ensemble,
        'scaler': scaler,
        'feature_names': feature_names,
        'metrics': {
            'accuracy': float(acc),
            'precision': float(prec),
            'recall': float(rec),
            'f1': float(f1),
            'confusion_matrix': cm.tolist()
        },
        'feature_importances': sorted_importances,
        'boosting_used': boosting_name
    }

    # Save model artifacts as model.pkl and models/phishing_model.joblib
    joblib.dump(model_package, MODEL_PKL)
    joblib.dump(model_package, MODEL_JOBLIB)

    print(f"\n[Artifact Saved] Model and Scaler successfully saved to '{MODEL_PKL}' and '{MODEL_JOBLIB}'.")
    return model_package

if __name__ == '__main__':
    train_ensemble_model()
