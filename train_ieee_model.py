import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
import pickle
import re
from urllib.parse import urlparse
from math import log2
import matplotlib.pyplot as plt
import seaborn as sns
import time
import shutil

print("="*60)
print("STEP 1: COMBINING DATASETS")
print("="*60)

# Load datasets
normal_df = pd.read_csv('ieee_dataset_final.csv')
hard_df = pd.read_csv('adversarial_test_set.csv')

print(f"📊 Normal dataset: {len(normal_df)} URLs")
print(f"📊 Hard dataset: {len(hard_df)} URLs")

# Combine them
combined_df = pd.concat([normal_df, hard_df], ignore_index=True)
combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
combined_df.to_csv('ieee_dataset_complete.csv', index=False)

print(f"\n✅ Combined dataset: {len(combined_df)} URLs")
print(f"   Phishing: {sum(combined_df['label'] == 1)}")
print(f"   Legitimate: {sum(combined_df['label'] == 0)}")

print("\n" + "="*60)
print("STEP 2: TRAINING ON REAL DATA")
print("="*60)

# Load the combined dataset
df = pd.read_csv('ieee_dataset_complete.csv')
print(f"✅ Loaded {len(df)} URLs")
print(f"   Phishing: {sum(df['label'] == 1)}")
print(f"   Legitimate: {sum(df['label'] == 0)}")

# Feature extraction function
def extract_features(url):
    """Extract 30 features from URL"""
    features = {}
    url_str = str(url).lower()
    
    try:
        parsed = urlparse(url_str)
        domain = parsed.netloc.split(':')[0]
    except:
        parsed = None
        domain = ''
    
    # Basic URL features
    features['URLLength'] = len(url_str)
    features['IsHTTPS'] = 1 if url_str.startswith('https') else 0
    features['DomainLength'] = len(domain)
    features['IsDomainIP'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0
    
    # Subdomain features
    subdomains = domain.split('.')
    features['NoOfSubDomain'] = max(0, len(subdomains) - 2)
    features['HasDeepSubdomain'] = 1 if features['NoOfSubDomain'] > 1 else 0
    
    # TLD features
    tld = subdomains[-1] if subdomains else ''
    features['TLDLength'] = len(tld)
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'click', 'loan', 'work', 'top', 'xyz', 'club']
    features['HasSuspiciousTLD'] = 1 if tld in suspicious_tlds else 0
    
    # Short URL services
    short_services = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly']
    features['IsShortenedURL'] = 1 if any(s in domain for s in short_services) else 0
    
    # Obfuscation
    features['HasObfuscation'] = 1 if '@' in url_str or '//' in url_str[8:] else 0
    features['NoOfObfuscatedChar'] = url_str.count('@') + url_str.count('%') + url_str.count('//')
    features['HasAtSymbol'] = 1 if '@' in url_str else 0
    features['HasDoubleSlash'] = 1 if '//' in url_str[8:] else 0
    
    # Character counts
    features['NoOfLettersInURL'] = sum(c.isalpha() for c in url_str)
    features['NoOfDigitsInURL'] = sum(c.isdigit() for c in url_str)
    features['LetterToDigitRatio'] = features['NoOfDigitsInURL'] / max(1, features['NoOfLettersInURL'])
    
    # Special characters
    special_chars = sum(not c.isalnum() for c in url_str)
    features['SpecialCharRatio'] = special_chars / max(1, len(url_str))
    features['NoOfEqualsInURL'] = url_str.count('=')
    features['NoOfQMarkInURL'] = url_str.count('?')
    features['NoOfAmpersandInURL'] = url_str.count('&')
    
    # Port and extensions
    features['HasPort'] = 1 if ':' in domain else 0
    suspicious_ext = ['exe', 'scr', 'zip', 'rar', 'doc', 'docx', 'xls', 'xlsx']
    path = parsed.path.lower() if parsed else ''
    features['HasSuspiciousFileExt'] = 1 if any(path.endswith(ext) for ext in suspicious_ext) else 0
    
    # Keywords
    keywords = ['secure', 'login', 'signin', 'verify', 'account', 'update', 
                'confirm', 'banking', 'paypal', 'apple', 'microsoft', 'amazon']
    features['SuspiciousKeywordCount'] = sum(url_str.count(k) for k in keywords)
    
    # Advanced
    features['DigitConcentration'] = features['NoOfDigitsInURL'] / max(1, len(url_str))
    
    # Entropy
    prob = [url_str.count(c)/max(1, len(url_str)) for c in set(url_str)]
    features['Entropy'] = -sum(p * log2(p) for p in prob if p > 0)
    
    # Consecutive consonants
    consonants = 'bcdfghjklmnpqrstvwxyz'
    max_cons = 0
    current = 0
    for c in url_str:
        if c in consonants:
            current += 1
            max_cons = max(max_cons, current)
        else:
            current = 0
    features['MaxConsecutiveConsonants'] = max_cons
    
    # Path features
    features['PathLength'] = len(parsed.path) if parsed else 0
    features['QueryLength'] = len(parsed.query) if parsed else 0
    features['HasFragment'] = 1 if parsed and parsed.fragment else 0
    features['URLDepth'] = parsed.path.count('/') if parsed else 0
    
    return features

# Extract features
print("\n🔧 Extracting features from URLs...")
features_list = []
for i, url in enumerate(df['url']):
    if i % 500 == 0:
        print(f"   Processed {i}/{len(df)} URLs")
    features_list.append(extract_features(url))

X = pd.DataFrame(features_list)
y = df['label']

print(f"\n✅ Extracted {X.shape[1]} features from {len(X)} URLs")

# Split data (70% train, 15% val, 15% test)
X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp)

print(f"\n📊 Dataset split:")
print(f"   Train: {len(X_train)} samples")
print(f"   Validation: {len(X_val)} samples")
print(f"   Test: {len(X_test)} samples")

# Train Random Forest
print("\n🌲 Training Random Forest...")
start_time = time.time()

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=25,
    min_samples_split=5,
    min_samples_leaf=2,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

train_time = time.time() - start_time
print(f"✅ Training completed in {train_time:.2f} seconds")

# Evaluate
train_acc = model.score(X_train, y_train)
val_acc = model.score(X_val, y_val)
test_acc = model.score(X_test, y_test)

print(f"\n📊 Accuracy:")
print(f"   Training: {train_acc:.2%}")
print(f"   Validation: {val_acc:.2%}")
print(f"   Test: {test_acc:.2%}")

# Detailed metrics
y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)[:, 1]

print("\n📋 Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)
print("\n📊 Confusion Matrix:")
print(f"               Predicted")
print(f"               Legit  Phishing")
print(f"Actual Legit    {cm[0,0]:5d}  {cm[0,1]:5d}")
print(f"Actual Phishing {cm[1,0]:5d}  {cm[1,1]:5d}")

# ROC-AUC
auc = roc_auc_score(y_test, y_proba)
print(f"\n📈 ROC-AUC Score: {auc:.4f}")

# Cross-validation
print("\n🔄 Performing 5-fold cross-validation...")
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores = cross_val_score(model, X, y, cv=cv, scoring='accuracy')
print(f"📊 CV Scores: {[f'{s:.2%}' for s in cv_scores]}")
print(f"🎯 Mean CV Accuracy: {cv_scores.mean():.2%} (+/- {cv_scores.std()*2:.2%})")

# Feature importance
importance = pd.DataFrame({
    'feature': X.columns,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

print("\n🔝 Top 10 Features:")
print(importance.head(10).to_string(index=False))

# Save model
print("\n💾 Saving model...")
with open('ieee_model.pkl', 'wb') as f:
    pickle.dump(model, f)

feature_info = {
    'feature_names': X.columns.tolist(),
    'accuracy': test_acc,
    'auc': auc,
    'cv_mean': cv_scores.mean()
}
with open('ieee_features.pkl', 'wb') as f:
    pickle.dump(feature_info, f)

print("✅ Model saved as 'ieee_model.pkl'")

# Update server
shutil.copy('ieee_model.pkl', 'server/native_model.pkl')
shutil.copy('ieee_features.pkl', 'server/feature_info.pkl')
print("✅ Server model updated")

print("\n" + "="*60)
print(f"🎯 FINAL TEST ACCURACY: {test_acc:.2%}")
print(f"   ROC-AUC: {auc:.4f}")
print(f"   Cross-val: {cv_scores.mean():.2%}")
print("="*60)

# Test on adversarial set again
print("\n" + "="*60)
print("STEP 3: TESTING ON ADVERSARIAL SET")
print("="*60)

# Load adversarial set
adv_df = pd.read_csv('adversarial_test_set.csv')
print(f"📊 Adversarial set: {len(adv_df)} URLs")

# Extract features
adv_features = []
for url in adv_df['url']:
    adv_features.append(extract_features(url))

X_adv = pd.DataFrame(adv_features)
y_adv = adv_df['label']

# Predict
y_adv_pred = model.predict(X_adv)
adv_acc = (y_adv_pred == y_adv).mean()

print(f"\n📊 Accuracy on adversarial set: {adv_acc:.2%}")

# Detailed report
print("\n📋 Classification Report:")
print(classification_report(y_adv, y_adv_pred, target_names=['Legitimate', 'Phishing']))

# Confusion matrix
cm_adv = confusion_matrix(y_adv, y_adv_pred)
print("\n📊 Confusion Matrix:")
print(f"               Predicted")
print(f"               Legit  Phishing")
print(f"Actual Legit    {cm_adv[0,0]:5d}  {cm_adv[0,1]:5d}")
print(f"Actual Phishing {cm_adv[1,0]:5d}  {cm_adv[1,1]:5d}")

print("\n" + "="*60)