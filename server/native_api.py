from flask import Flask, request, jsonify
import pickle
import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
import os

app = Flask(__name__)

# ============================================================================
# IMPORTANT: DEFINE THE SAME CLASSES AS IN TRAINING
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
        features = {}
        url_lower = url.lower()
        
        features['is_https'] = 1 if url.startswith('https') else 0
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0]
            
            features['is_known_legit'] = 0
            for legit in self.known_legit_domains:
                if legit in domain:
                    features['is_known_legit'] = 1
                    break
            
            parts = domain.split('.')
            if len(parts) >= 2:
                tld = parts[-1]
                features['has_suspicious_tld'] = 1 if tld in self.suspicious_tlds else 0
            else:
                features['has_suspicious_tld'] = 0
            
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            features['is_ip'] = 1 if re.match(ip_pattern, domain) else 0
            
            features['has_port'] = 1 if ':' in parsed.netloc else 0
            
        except:
            features['is_known_legit'] = 0
            features['has_suspicious_tld'] = 0
            features['is_ip'] = 0
            features['has_port'] = 0
        
        features['has_at'] = 1 if '@' in url else 0
        
        keyword_count = 0
        for keyword in self.suspicious_keywords:
            if keyword in url_lower:
                keyword_count += 1
        features['suspicious_words'] = min(keyword_count, 3)
        
        features['url_length'] = min(len(url), 200) / 200
        features['has_query'] = 1 if '?' in url else 0
        features['digit_count'] = min(sum(c.isdigit() for c in url), 20) / 20
        
        return features

# ============================================================================
# LOAD MODEL
# ============================================================================
print("Loading PhiUSIIL model...")

try:
    with open('native_model.pkl', 'rb') as f:
        model_data = pickle.load(f)
    
    # Reconstruct model with our class definition
    model = SimplePhishingDetector()
    # Copy rules from saved model
    if 'rules' in model_data:
        model.rules = model_data['rules']
    
    FEATURES = model_data['features']
    accuracy = model_data.get('accuracy', 0)
    
    print(f"✅ Model loaded successfully!")
    print(f"   Accuracy: {accuracy:.4f}")
    print(f"   Features: {len(FEATURES)}")
    
except Exception as e:
    print(f"❌ Error loading model: {e}")
    print("   Make sure to train the model first: python final_training.py")
    model = None
    FEATURES = []
    accuracy = 0

extractor = RealisticFeatureExtractor()

# ============================================================================
# API ENDPOINTS
# ============================================================================
@app.after_request
def add_cors_headers(response):
    """Add CORS headers to allow Chrome extension access"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy' if model else 'unhealthy',
        'model_loaded': model is not None,
        'accuracy': accuracy,
        'features': len(FEATURES),
        'service': 'PhiUSIIL Phishing Detector API v1.0'
    })

@app.route('/predict', methods=['POST', 'OPTIONS'])
def predict():
    """Main prediction endpoint"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        # Get URL from request
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'error': 'No URL provided',
                'status': 'error'
            }), 400
        
        url = data['url'].strip()
        
        if not url:
            return jsonify({
                'error': 'Empty URL',
                'status': 'error'
            }), 400
        
        # Check model
        if model is None:
            return jsonify({
                'error': 'Model not loaded',
                'status': 'error'
            }), 503
        
        # Extract features
        features = extractor.extract(url)
        
        # Create DataFrame with correct feature order
        df = pd.DataFrame([features])
        
        # Ensure all expected features exist
        for feature in FEATURES:
            if feature not in df.columns:
                df[feature] = 0
        
        # Reorder to match training
        df = df[FEATURES]
        
        # Make prediction
        prediction_proba = model.predict_proba(df)[0]
        prediction_idx = model.predict(df)[0]
        
        # Map to labels
        labels = ['legitimate', 'phishing']
        prediction = labels[prediction_idx]
        probability = float(prediction_proba[prediction_idx])
        confidence = probability * 100
        
        # Get reasons for prediction
        reasons = []
        
        if features.get('has_suspicious_tld') == 1:
            reasons.append('Suspicious TLD (.tk, .ml, .ga, etc.)')
        
        if features.get('is_ip') == 1:
            reasons.append('Uses IP address instead of domain name')
        
        if features.get('has_at') == 1:
            reasons.append('Contains @ symbol (credential embedding)')
        
        if features.get('is_https') == 0:
            reasons.append('Uses HTTP instead of HTTPS')
        
        if features.get('suspicious_words', 0) >= 2:
            reasons.append(f'Contains {features["suspicious_words"]} suspicious keywords')
        
        if features.get('is_known_legit') == 1:
            reasons.append('Known legitimate website')
        
        # Prepare response
        response = {
            'url': url,
            'prediction': prediction,
            'probability': probability,
            'confidence': round(confidence, 1),
            'reasons': reasons[:3],  # Top 3 reasons
            'status': 'success',
            'features_analyzed': len(FEATURES)
        }
        
        return jsonify(response)
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error',
            'prediction': 'unknown',
            'probability': 0.5
        }), 500

@app.route('/features', methods=['POST', 'OPTIONS'])
def get_features():
    """Extract features without prediction"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'No URL provided'}), 400
        
        url = data['url'].strip()
        features = extractor.extract(url)
        
        return jsonify({
            'url': url,
            'features': features,
            'count': len(features),
            'status': 'success'
        })
    
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'}), 500

# ============================================================================
# START SERVER
# ============================================================================
if __name__ == '__main__':
    print("\n" + "="*60)
    print("PHIUSIIL API SERVER")
    print("="*60)
    print("📡 Endpoints:")
    print("  POST /predict    - Check URL for phishing")
    print("  POST /features   - Extract URL features")
    print("  GET  /health     - Health check")
    print("\n📍 Running on: http://localhost:5000")
    print("📌 Press Ctrl+C to stop")
    print("="*60)
    
    app.run(host='0.0.0.0', port=5000, debug=False)