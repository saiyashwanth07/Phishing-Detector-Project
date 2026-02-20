import pandas as pd
import numpy as np
import pickle
import warnings
warnings.filterwarnings('ignore')
import os
import re
from urllib.parse import urlparse

# ============================================================================
# REALISTIC FEATURE EXTRACTOR
# ============================================================================
class RealisticFeatureExtractor:
    def __init__(self):
        self.suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'xyz', 'top']
        self.known_legit_domains = [
            'google.com', 'github.com', 'youtube.com', 'wikipedia.org',
            'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com',
            'microsoft.com', 'apple.com', 'paypal.com', 'ebay.com',
            'stackoverflow.com', 'reddit.com', 'netflix.com'
        ]
        self.suspicious_keywords = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'password', 'banking']
    
    def extract(self, url):
        """Extract 10 key features for phishing detection"""
        features = {}
        url_lower = url.lower()
        
        # 1. HTTPS (phishing often uses HTTP)
        features['is_https'] = 1 if url.startswith('https') else 0
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0]
            
            # 2. Known legitimate domain
            features['is_known_legit'] = 0
            for legit in self.known_legit_domains:
                if legit in domain:
                    features['is_known_legit'] = 1
                    break
            
            # 3. Suspicious TLD (.tk, .ml, etc.)
            parts = domain.split('.')
            if len(parts) >= 2:
                tld = parts[-1]
                features['has_suspicious_tld'] = 1 if tld in self.suspicious_tlds else 0
            else:
                features['has_suspicious_tld'] = 0
            
            # 4. IP address (very suspicious)
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            features['is_ip'] = 1 if re.match(ip_pattern, domain) else 0
            
            # 5. Port number (non-standard ports suspicious)
            features['has_port'] = 1 if ':' in parsed.netloc else 0
            
        except:
            features['is_known_legit'] = 0
            features['has_suspicious_tld'] = 0
            features['is_ip'] = 0
            features['has_port'] = 0
        
        # 6. @ symbol (credential embedding attack)
        features['has_at'] = 1 if '@' in url else 0
        
        # 7. Suspicious keywords in URL
        keyword_count = 0
        for keyword in self.suspicious_keywords:
            if keyword in url_lower:
                keyword_count += 1
        features['suspicious_words'] = min(keyword_count, 3)  # Cap at 3
        
        # 8. URL length (phishing URLs often longer)
        features['url_length'] = min(len(url), 200) / 200
        
        # 9. Has query parameters (?)
        features['has_query'] = 1 if '?' in url else 0
        
        # 10. Number of digits (phishing often has many digits)
        features['digit_count'] = min(sum(c.isdigit() for c in url), 20) / 20
        
        return features

# ============================================================================
# SIMPLE RULE-BASED CLASSIFIER
# ============================================================================
class SimplePhishingDetector:
    def __init__(self):
        # Rules that make sense for real-world phishing
        self.rules = [
            ('is_known_legit', 1, 0.8, False),      # Known legitimate site
            ('has_suspicious_tld', 1, 0.7, True),   # Suspicious TLD
            ('is_ip', 1, 0.9, True),               # IP address (very suspicious)
            ('has_at', 1, 0.95, True),             # @ symbol (definitely phishing)
            ('is_https', 0, 0.6, True),            # HTTP (not HTTPS)
            ('suspicious_words', 2, 0.5, True),    # 2+ suspicious keywords
            ('has_port', 1, 0.4, True),            # Non-standard port
            ('digit_count', 0.3, 0.3, True),       # Many digits
        ]
    
    def predict(self, X):
        """Predict phishing (1) or legitimate (0)"""
        scores = self.predict_proba(X)
        return (scores[:, 1] > 0.5).astype(int)
    
    def predict_proba(self, X):
        """Return probability scores"""
        n_samples = len(X)
        scores = np.zeros((n_samples, 2))  # [legitimate, phishing]
        
        for i in range(n_samples):
            phishing_score = 0.0
            legitimate_score = 0.0
            
            # Apply each rule
            for feature, threshold, weight, is_phishing in self.rules:
                if feature in X.columns:
                    if feature in ['suspicious_words', 'digit_count', 'url_length']:
                        # For numeric features, check if >= threshold
                        if X.iloc[i][feature] >= threshold:
                            if is_phishing:
                                phishing_score += weight
                            else:
                                legitimate_score += weight
                    else:
                        # For binary features, check if == threshold
                        if X.iloc[i][feature] == threshold:
                            if is_phishing:
                                phishing_score += weight
                            else:
                                legitimate_score += weight
            
            # Base score (slight bias toward legitimate)
            legitimate_score += 0.1
            
            # Normalize to probabilities
            total = phishing_score + legitimate_score
            if total > 0:
                scores[i, 0] = legitimate_score / total
                scores[i, 1] = phishing_score / total
            else:
                scores[i, 0] = 0.5
                scores[i, 1] = 0.5
        
        return scores

# ============================================================================
# MAIN TRAINING FUNCTION
# ============================================================================
def main():
    print("="*70)
    print("PHIUSIIL - FINAL MODEL TRAINING")
    print("="*70)
    
    # Load realistic dataset
    print("\n[1/3] Loading realistic dataset...")
    df = pd.read_csv('realistic_dataset.csv')
    print(f"   URLs: {len(df)}")
    print(f"   Legitimate: {sum(df['label'] == 0)}")
    print(f"   Phishing: {sum(df['label'] == 1)}")
    
    # Extract features
    print("\n[2/3] Extracting features...")
    extractor = RealisticFeatureExtractor()
    features_list = []
    
    for idx, url in enumerate(df['URL']):
        features = extractor.extract(str(url))
        features_list.append(features)
        
        if (idx + 1) % 2000 == 0:
            print(f"   Processed {idx + 1} URLs...")
    
    X = pd.DataFrame(features_list)
    y = df['label'].values
    
    print(f"\n   Features extracted: {len(X.columns)}")
    print(f"   Feature names: {list(X.columns)}")
    
    # Split data
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    
    # Create and test model
    print("\n[3/3] Training classifier...")
    model = SimplePhishingDetector()
    
    # Test accuracy
    y_pred = model.predict(X_test)
    accuracy = np.mean(y_pred == y_test)
    
    print(f"\n" + "="*70)
    print("MODEL PERFORMANCE")
    print("="*70)
    print(f"Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    # Detailed metrics
    tp = np.sum((y_test == 1) & (y_pred == 1))
    tn = np.sum((y_test == 0) & (y_pred == 0))
    fp = np.sum((y_test == 0) & (y_pred == 1))
    fn = np.sum((y_test == 1) & (y_pred == 0))
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    print(f"\nDetailed Metrics:")
    print(f"  Precision: {precision:.4f} ({precision*100:.1f}%)")
    print(f"  Recall:    {recall:.4f} ({recall*100:.1f}%)")
    print(f"  F1-Score:  {f1:.4f} ({f1*100:.1f}%)")
    
    print(f"\nConfusion Matrix:")
    print(f"               Predicted")
    print(f"               Legit   Phishing")
    print(f"Actual Legit   {tn:6d}   {fp:6d}")
    print(f"       Phishing {fn:6d}   {tp:6d}")
    
    # Save model
    print("\n[SAVING] Saving model...")
    os.makedirs('server', exist_ok=True)
    
    model_data = {
        'model': model,
        'extractor': extractor,
        'features': X.columns.tolist(),
        'accuracy': accuracy,
        'metrics': {
            'precision': precision,
            'recall': recall,
            'f1_score': f1
        },
        'rules': model.rules
    }
    
    with open('server/native_model.pkl', 'wb') as f:
        pickle.dump(model_data, f)
    
    # Save feature info
    feature_info = {
        'feature_names': X.columns.tolist(),
        'num_features': len(X.columns),
        'rules': model.rules
    }
    
    with open('server/feature_info.pkl', 'wb') as f:
        pickle.dump(feature_info, f)
    
    print(f"✅ Model saved: server/native_model.pkl")
    print(f"✅ Feature info saved: server/feature_info.pkl")
    
    # REAL-WORLD TEST
    print(f"\n" + "="*70)
    print("REAL-WORLD VALIDATION")
    print("="*70)
    
    test_cases = [
        # (URL, Expected, Description)
        ('https://www.google.com', 'Legitimate', 'Known legitimate site'),
        ('https://github.com/login', 'Legitimate', 'GitHub login (real)'),
        ('http://secure-login.tk', 'Phishing', 'Suspicious TLD'),
        ('http://192.168.1.1:8080', 'Phishing', 'IP address with port'),
        ('https://apple-id-confirm.ga', 'Phishing', 'Brand impersonation'),
        ('https://www.paypal.com', 'Legitimate', 'Real PayPal'),
        ('http://update-account.xyz/login.php', 'Phishing', 'Suspicious keywords'),
        ('https://facebook.com@evil.tk', 'Phishing', '@ symbol attack'),
        ('https://stackoverflow.com', 'Legitimate', 'Known site'),
        ('http://tinyurl.com/abc123', 'Phishing', 'Shortened URL'),
    ]
    
    print("\n" + "URL".ljust(50) + "Expected".ljust(15) + "Predicted".ljust(15) + "Result")
    print("-" * 100)
    
    correct = 0
    for url, expected, description in test_cases:
        features = extractor.extract(url)
        df_test = pd.DataFrame([features])[X.columns]
        pred = model.predict(df_test)[0]
        proba = model.predict_proba(df_test)[0]
        
        predicted = 'Phishing' if pred == 1 else 'Legitimate'
        is_correct = predicted == expected
        
        if is_correct:
            correct += 1
            mark = "✅"
        else:
            mark = "❌"
        
        print(f"{mark} {url[:48]:50s} {expected:15s} {predicted:15s} ({proba[1]:.1%})")
    
    accuracy_real = correct / len(test_cases)
    print(f"\nReal-world accuracy: {correct}/{len(test_cases)} ({accuracy_real*100:.1f}%)")
    
    if accuracy_real >= 0.9:
        print("🎉 EXCELLENT! Model works perfectly!")
    elif accuracy_real >= 0.7:
        print("✅ GOOD! Model works well.")
    else:
        print("⚠️  Model needs improvement.")
    
    print(f"\n" + "="*70)
    print("NEXT STEPS")
    print("="*70)
    print("1. Start API server: python server/native_api.py")
    print("2. Test API: python test_api.py")
    print("3. Load Chrome extension")
    print("4. Visit test URLs to see real-time detection")
    
    return model, extractor, accuracy

# ============================================================================
# RUN TRAINING
# ============================================================================
if __name__ == '__main__':
    model, extractor, accuracy = main()
    
    # Quick API test
    print(f"\n" + "="*70)
    print("QUICK API TEST")
    print("="*70)
    
    # Create a simple test
    test_url = "https://www.google.com"
    features = extractor.extract(test_url)
    X_columns = list(features.keys())
    df_test = pd.DataFrame([features])[X_columns]
    pred = model.predict(df_test)[0]
    proba = model.predict_proba(df_test)[0]
    
    print(f"\nTest URL: {test_url}")
    print(f"Prediction: {'Phishing' if pred == 1 else 'Legitimate'}")
    print(f"Confidence: {proba[pred]*100:.1f}%")
    
    print(f"\n🎯 Training complete! Accuracy: {accuracy*100:.1f}%")