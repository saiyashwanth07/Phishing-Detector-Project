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

# Simple feature extractor
class SimpleFeatureExtractor:
    def __init__(self):
        self.suspicious_keywords = ['login', 'verify', 'secure', 'account']
        self.suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'xyz']
    
    def extract(self, url):
        features = {}
        features['url_length'] = len(url)
        features['is_https'] = 1 if url.startswith('https') else 0
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0]
            features['domain_length'] = len(domain)
            
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            features['is_ip_address'] = 1 if re.match(ip_pattern, domain) else 0
            
            parts = domain.split('.')
            if len(parts) >= 2:
                tld = parts[-1].lower()
                features['has_suspicious_tld'] = 1 if tld in self.suspicious_tlds else 0
            else:
                features['has_suspicious_tld'] = 0
                
            features['has_port'] = 1 if ':' in parsed.netloc else 0
            
        except:
            features['domain_length'] = 0
            features['is_ip_address'] = 0
            features['has_suspicious_tld'] = 0
            features['has_port'] = 0
        
        url_lower = url.lower()
        features['has_at_symbol'] = 1 if '@' in url else 0
        
        keyword_count = 0
        for keyword in self.suspicious_keywords:
            if keyword in url_lower:
                keyword_count += 1
        features['suspicious_keyword_count'] = keyword_count
        
        return features

# Load and analyze data
print("="*70)
print("DEBUGGING DATASET")
print("="*70)

# Load dataset
df = pd.read_csv('dataset/PhiUSIIL_Phishing_URL_Dataset.csv')
df_sample = df.sample(n=1000, random_state=42)

print(f"Sample size: {len(df_sample)}")
print(f"Phishing: {sum(df_sample['label'] == 1)}")
print(f"Legitimate: {sum(df_sample['label'] == 0)}")

# Extract features
extractor = SimpleFeatureExtractor()
features_list = []

for url in df_sample['URL']:
    features = extractor.extract(str(url))
    features_list.append(features)

X = pd.DataFrame(features_list)
y = df_sample['label'].values

print(f"\nFeatures extracted: {list(X.columns)}")

# Analyze each feature
print(f"\n" + "="*70)
print("FEATURE ANALYSIS")
print("="*70)

for feature in X.columns:
    phishing_mean = y[X[feature] == 1].mean() if len(X[X[feature] == 1]) > 0 else 0
    legitimate_mean = y[X[feature] == 0].mean() if len(X[X[feature] == 0]) > 0 else 0
    
    print(f"\n{feature}:")
    print(f"  When feature = 1: {len(X[X[feature] == 1])} samples, {phishing_mean:.1%} phishing")
    print(f"  When feature = 0: {len(X[X[feature] == 0])} samples, {legitimate_mean:.1%} phishing")
    
    # Rule suggestion
    if feature in ['has_suspicious_tld', 'is_ip_address', 'has_at_symbol']:
        if phishing_mean > 0.7:
            print(f"  ✅ Good rule: {feature}=1 → Phishing ({phishing_mean:.1%})")
        else:
            print(f"  ⚠️  Weak rule: {feature}=1 → Only {phishing_mean:.1%} phishing")
    
    if feature == 'is_https':
        http_phishing_rate = y[X['is_https'] == 0].mean()
        if http_phishing_rate > 0.6:
            print(f"  ✅ Good rule: HTTPS=0 (HTTP) → Phishing ({http_phishing_rate:.1%})")
        else:
            print(f"  ⚠️  HTTP phishing rate: {http_phishing_rate:.1%}")

# Check URLs
print(f"\n" + "="*70)
print("SAMPLE URL ANALYSIS")
print("="*70)

# Look at some phishing URLs
phishing_urls = df_sample[df_sample['label'] == 1]['URL'].head(5).tolist()
legitimate_urls = df_sample[df_sample['label'] == 0]['URL'].head(5).tolist()

print("\nPhishing URLs:")
for url in phishing_urls[:3]:
    print(f"  {url[:80]}...")

print("\nLegitimate URLs:")
for url in legitimate_urls[:3]:
    print(f"  {url[:80]}...")

# Check HTTPS usage
print(f"\n" + "="*70)
print("HTTPS ANALYSIS")
print("="*70)

phishing_https = sum((df_sample['label'] == 1) & 
                     (df_sample['URL'].str.startswith('https', na=False))) / sum(df_sample['label'] == 1)
legitimate_https = sum((df_sample['label'] == 0) & 
                       (df_sample['URL'].str.startswith('https', na=False))) / sum(df_sample['label'] == 0)

print(f"Phishing URLs using HTTPS: {phishing_https:.1%}")
print(f"Legitimate URLs using HTTPS: {legitimate_https:.1%}")

if phishing_https > 0.8 and legitimate_https < 0.5:
    print("⚠️  Dataset bias: Most phishing uses HTTPS, most legitimate uses HTTP")
    print("   This will confuse the model!")