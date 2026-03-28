from flask import Flask, request, jsonify
from feature_extractor import FastFeatureExtractor
import pickle
import pandas as pd
import numpy as np
import time

app = Flask(__name__)

print("="*60)
print("LOADING MODEL...")
print("="*60)

# Load model
model = None
feature_names = []

try:
    with open('ieee_model.pkl', 'rb') as f:
        model = pickle.load(f)
    print("✅ Loaded ieee_model.pkl")
    
    try:
        with open('ieee_features.pkl', 'rb') as f:
            feature_data = pickle.load(f)
            if isinstance(feature_data, dict):
                feature_names = feature_data.get('feature_names', [])
            elif isinstance(feature_data, list):
                feature_names = feature_data
        print(f"✅ Loaded {len(feature_names)} features")
    except Exception as e:
        print(f"⚠️ No feature file found: {e}")
        
except Exception as e:
    print(f"❌ Error loading model: {e}")
    model = None

if model is None:
    print("⚠️ Running in fallback mode")
else:
    print(f"✅ Model type: {type(model)}")
    print(f"✅ Model ready for predictions")

# Initialize fast extractor
extractor = FastFeatureExtractor()

# Middleware to log latency
@app.before_request
def before_request():
    request.start_time = time.time()

@app.after_request
def after_request(response):
    if hasattr(request, 'start_time'):
        elapsed = time.time() - request.start_time
        print(f"⏱️  Request latency: {elapsed*1000:.2f}ms")
    return response

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'model_type': str(type(model)) if model else 'fallback',
        'features_loaded': len(feature_names)
    })

@app.route('/predict', methods=['POST', 'OPTIONS'])
def predict():
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'No URL provided'}), 400
        
        url = data['url'].strip()
        if not url:
            return jsonify({'error': 'Empty URL'}), 400
        
        # Extract features using fast extractor
        features = extractor.extract(url)
        
        # If model not loaded, return error
        if model is None:
            return jsonify({
                'error': 'Model not loaded',
                'status': 'error'
            }), 503
        
        # Create DataFrame with correct feature order
        df = pd.DataFrame([features])
        
        # Ensure all expected features exist
        for feature in feature_names:
            if feature not in df.columns:
                df[feature] = 0
        
        # Reorder to match training
        df = df[feature_names]
        
        # Make prediction
        proba = model.predict_proba(df)[0]
        pred = model.predict(df)[0]
        confidence = float(proba[pred]) * 100
        
        prediction = 'phishing' if pred == 1 else 'legitimate'
        
        # Add feature importance for top 3 reasons (optional)
        reasons = []
        if prediction == 'phishing':
            if features.get('SuspiciousKeywordCount', 0) > 0:
                reasons.append("Contains suspicious keywords")
            if features.get('HasSuspiciousTLD', 0) == 1:
                reasons.append("Uses suspicious TLD")
            if features.get('IsDomainIP', 0) == 1:
                reasons.append("Uses IP address instead of domain")
            if features.get('HasAtSymbol', 0) == 1:
                reasons.append("Contains @ symbol")
            if features.get('IsHTTPS', 1) == 0:
                reasons.append("Uses HTTP instead of HTTPS")
        
        return jsonify({
            'url': url,
            'prediction': prediction,
            'confidence': round(confidence, 1),
            'probability': confidence / 100,
            'reasons': reasons[:3],  # Top 3 reasons
            'features_analyzed': len(features),
            'mode': 'ml'
        })
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error',
            'prediction': 'unknown',
            'confidence': 0
        }), 500

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 OPTIMIZED API SERVER")
    print("="*60)
    print("📍 Running on: http://localhost:5000")
    print("📌 Endpoints:")
    print("   GET  /health   - Health check")
    print("   POST /predict  - URL prediction")
    print("\n📊 Performance: Expected latency <100ms")
    print("📌 Press Ctrl+C to stop")
    print("="*60)
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)