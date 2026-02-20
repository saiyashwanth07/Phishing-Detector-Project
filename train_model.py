import pandas as pd
import numpy as np
import pickle
import warnings
warnings.filterwarnings('ignore')
import sys
import os
import re
from urllib.parse import urlparse
import math

# ============================================================================
# SIMPLE FEATURE EXTRACTOR (Built-in)
# ============================================================================
class SimpleFeatureExtractor:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'signin', 'verify', 'secure', 'account', 'banking',
            'update', 'confirm', 'password', 'wallet', 'paypal', 'ebay',
            'amazon', 'apple', 'microsoft', 'support', 'service', 'alert'
        ]
        
        self.suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top']
    
    def extract(self, url):
        """Extract 15 simple features from URL"""
        features = {}
        
        # 1. URL length
        features['url_length'] = len(url)
        
        # 2. HTTPS or HTTP
        features['is_https'] = 1 if url.startswith('https') else 0
        
        # Parse URL
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0] if parsed.netloc else ''
            
            # 3. Domain length
            features['domain_length'] = len(domain)
            
            # 4. IP address check
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            features['is_ip_address'] = 1 if re.match(ip_pattern, domain) else 0
            
            # 5. Subdomain count
            subdomain_count = domain.count('.') - 1
            features['num_subdomains'] = max(0, subdomain_count)
            
            # 6. Suspicious TLD
            parts = domain.split('.')
            if len(parts) >= 2:
                tld = parts[-1].lower()
                features['has_suspicious_tld'] = 1 if tld in self.suspicious_tlds else 0
            else:
                features['has_suspicious_tld'] = 0
            
            # 7. Port number
            features['has_port'] = 1 if ':' in parsed.netloc else 0
            
        except:
            features['domain_length'] = 0
            features['is_ip_address'] = 0
            features['num_subdomains'] = 0
            features['has_suspicious_tld'] = 0
            features['has_port'] = 0
        
        # 8. @ symbol (credential embedding)
        features['has_at_symbol'] = 1 if '@' in url else 0
        
        # 9. Obfuscation (% encoding)
        features['has_obfuscation'] = 1 if '%' in url else 0
        
        # 10-11. Character counts
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_special_chars'] = sum(not c.isalnum() for c in url)
        
        # 12. Suspicious keywords
        url_lower = url.lower()
        keyword_count = 0
        for keyword in self.suspicious_keywords:
            if keyword in url_lower:
                keyword_count += 1
        features['suspicious_keyword_count'] = keyword_count
        
        # 13. Query parameters
        features['num_equals'] = url.count('=')
        features['num_question_marks'] = url.count('?')
        
        # 14. Path depth
        try:
            parsed = urlparse(url)
            features['url_depth'] = parsed.path.count('/')
        except:
            features['url_depth'] = 0
        
        # 15. Entropy (randomness)
        if url:
            prob = [float(url.count(c)) / len(url) for c in set(url)]
            features['entropy'] = -sum(p * math.log2(p) for p in prob if p > 0)
        else:
            features['entropy'] = 0
        
        return features

# ============================================================================
# RULE-BASED CLASSIFIER
# ============================================================================
class RuleBasedClassifier:
    """Simple rule-based classifier that always works"""
    def __init__(self):
        self.rules = []
        self.threshold = 0.5
    
    def fit(self, X, y):
        """Learn rules from data"""
        print("Learning rules from data...")
        
        # Rule 1: Suspicious TLD
        if 'has_suspicious_tld' in X.columns:
            tld_phishing_rate = y[X['has_suspicious_tld'] == 1].mean()
            if tld_phishing_rate > 0.7:
                self.rules.append(('has_suspicious_tld', 1, 0.8))
        
        # Rule 2: IP address
        if 'is_ip_address' in X.columns:
            ip_phishing_rate = y[X['is_ip_address'] == 1].mean()
            if ip_phishing_rate > 0.7:
                self.rules.append(('is_ip_address', 1, 0.7))
        
        # Rule 3: Has @ symbol
        if 'has_at_symbol' in X.columns:
            at_phishing_rate = y[X['has_at_symbol'] == 1].mean()
            if at_phishing_rate > 0.6:
                self.rules.append(('has_at_symbol', 1, 0.6))
        
        # Rule 4: HTTP (not HTTPS)
        if 'is_https' in X.columns:
            http_phishing_rate = y[X['is_https'] == 0].mean()
            if http_phishing_rate > 0.6:
                self.rules.append(('is_https', 0, 0.5))
        
        # Rule 5: Many suspicious keywords
        if 'suspicious_keyword_count' in X.columns:
            X['high_keywords'] = (X['suspicious_keyword_count'] > 2).astype(int)
            kw_phishing_rate = y[X['high_keywords'] == 1].mean()
            if kw_phishing_rate > 0.6:
                self.rules.append(('suspicious_keyword_count', 2, 0.4))
        
        print(f"Learned {len(self.rules)} rules")
    
    def predict(self, X):
        """Predict using rules"""
        scores = self.predict_proba(X)
        return (scores[:, 1] > self.threshold).astype(int)
    
    def predict_proba(self, X):
        """Predict probabilities"""
        n_samples = len(X)
        scores = np.zeros((n_samples, 2))
        
        for i in range(n_samples):
            phishing_score = 0.0
            legitimate_score = 0.0
            
            # Apply each rule
            for feature, threshold, weight in self.rules:
                if feature == 'suspicious_keyword_count':
                    if X.iloc[i][feature] > threshold:
                        phishing_score += weight
                else:
                    if X.iloc[i][feature] == threshold:
                        phishing_score += weight
            
            # Base score (bias toward legitimate)
            legitimate_score = 0.3
            
            # Normalize
            total = phishing_score + legitimate_score
            if total > 0:
                scores[i, 0] = legitimate_score / total  # Legitimate probability
                scores[i, 1] = phishing_score / total    # Phishing probability
            else:
                scores[i, 0] = 0.5
                scores[i, 1] = 0.5
        
        return scores
    
    def get_rules(self):
        """Get human-readable rules"""
        rule_descriptions = []
        for feature, threshold, weight in self.rules:
            if feature == 'has_suspicious_tld':
                rule_descriptions.append(f"If URL has suspicious TLD (.tk, .ml, etc): +{weight:.1f}")
            elif feature == 'is_ip_address':
                rule_descriptions.append(f"If URL uses IP address instead of domain: +{weight:.1f}")
            elif feature == 'has_at_symbol':
                rule_descriptions.append(f"If URL contains '@' symbol: +{weight:.1f}")
            elif feature == 'is_https':
                rule_descriptions.append(f"If URL uses HTTP (not HTTPS): +{weight:.1f}")
            elif feature == 'suspicious_keyword_count':
                rule_descriptions.append(f"If URL has >{threshold} suspicious keywords: +{weight:.1f}")
        
        return rule_descriptions

# ============================================================================
# MAIN TRAINING FUNCTION
# ============================================================================
def train_model():
    print("="*70)
    print("PHIUSIIL PHISHING DETECTOR - RULE-BASED TRAINING")
    print("="*70)
    
    # Load dataset
    print("\n[1/4] Loading dataset...")
    df = pd.read_csv('dataset/PhiUSIIL_Phishing_URL_Dataset.csv')
    print(f"   Loaded {len(df)} URLs")
    
    # Use smaller sample for faster training
    sample_size = min(20000, len(df))
    df_sample = df.sample(n=sample_size, random_state=42)
    print(f"   Using sample of {len(df_sample)} URLs")
    
    # Extract features
    print("\n[2/4] Extracting features...")
    extractor = SimpleFeatureExtractor()
    features_list = []
    
    for idx, url in enumerate(df_sample['URL']):
        if pd.isna(url):
            url = ''
        features = extractor.extract(str(url))
        features_list.append(features)
        
        if (idx + 1) % 5000 == 0:
            print(f"   Processed {idx + 1} URLs...")
    
    X = pd.DataFrame(features_list)
    y = df_sample['label'].values
    
    print(f"   Extracted {X.shape[1]} features")
    
    # Train rule-based model
    print("\n[3/4] Training Rule-Based Classifier...")
    model = RuleBasedClassifier()
    model.fit(X, y)
    
    # Evaluate
    print("\n[4/4] Evaluating...")
    y_pred = model.predict(X)
    accuracy = np.mean(y_pred == y)
    
    print(f"\n" + "="*70)
    print("RESULTS")
    print("="*70)
    print(f"Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    # Confusion matrix
    tp = np.sum((y == 1) & (y_pred == 1))
    tn = np.sum((y == 0) & (y_pred == 0))
    fp = np.sum((y == 0) & (y_pred == 1))
    fn = np.sum((y == 1) & (y_pred == 0))
    
    print(f"\nConfusion Matrix:")
    print(f"               Predicted")
    print(f"               Legit   Phishing")
    print(f"Actual Legit   {tn:6d}   {fp:6d}")
    print(f"       Phishing {fn:6d}   {tp:6d}")
    
    # Show learned rules
    print(f"\n" + "="*70)
    print("LEARNED RULES:")
    print("="*70)
    rules = model.get_rules()
    for i, rule in enumerate(rules, 1):
        print(f"{i}. {rule}")
    
    # Save model
    print("\n[SAVING] Saving model...")
    model_data = {
        'model': model,
        'extractor': extractor,
        'features': X.columns.tolist(),
        'accuracy': accuracy,
        'rules': model.get_rules(),
        'model_type': 'RuleBasedClassifier'
    }
    
    # Create server directory if it doesn't exist
    os.makedirs('server', exist_ok=True)
    
    with open('server/native_model.pkl', 'wb') as f:
        pickle.dump(model_data, f)
    
    # Save feature info
    feature_info = {
        'feature_names': X.columns.tolist(),
        'num_features': len(X.columns),
        'rules': model.get_rules()
    }
    
    with open('server/feature_info.pkl', 'wb') as f:
        pickle.dump(feature_info, f)
    
    print(f"✅ Model saved: server/native_model.pkl")
    print(f"✅ Feature info saved: server/feature_info.pkl")
    print(f"✅ Final accuracy: {accuracy:.4f}")
    
    # Quick test
    print(f"\n" + "="*70)
    print("QUICK TEST")
    print("="*70)
    
    test_urls = [
        ('https://www.google.com', 'Legitimate'),
        ('https://github.com', 'Legitimate'),
        ('http://secure-login.tk', 'Phishing'),
        ('http://192.168.1.1:8080', 'Phishing'),
        ('https://apple-id-confirm.ga', 'Phishing'),
        ('https://www.paypal.com', 'Legitimate'),
    ]
    
    correct = 0
    for url, expected in test_urls:
        features = extractor.extract(url)
        df_test = pd.DataFrame([features])[X.columns]
        pred = model.predict(df_test)[0]
        proba = model.predict_proba(df_test)[0]
        
        result = 'Phishing' if pred == 1 else 'Legitimate'
        is_correct = result == expected
        
        if is_correct:
            correct += 1
            mark = "✅"
        else:
            mark = "❌"
        
        print(f"{mark} {url[:45]:45s} -> {result:12s} (Phishing: {proba[1]:.1%})")
    
    print(f"\nTest accuracy: {correct}/{len(test_urls)} ({correct/len(test_urls)*100:.0f}%)")
    print(f"\n🎯 Training complete! Run: python server/native_api.py")

# ============================================================================
# RUN TRAINING
# ============================================================================
if __name__ == '__main__':
    train_model()