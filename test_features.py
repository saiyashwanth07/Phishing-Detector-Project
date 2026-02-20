import sys
sys.path.append('server')

try:
    from feature_extractor import URLFeatureExtractor
    print("✅ Using URLFeatureExtractor")
except:
    print("⚠️  Creating simple extractor...")
    import re
    from urllib.parse import urlparse
    import math
    
    class URLFeatureExtractor:
        def __init__(self):
            self.suspicious_keywords = ['login', 'verify', 'secure', 'account']
            self.suspicious_tlds = ['tk', 'ml', 'ga', 'cf']
        
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
                    
            except:
                features['domain_length'] = 0
                features['is_ip_address'] = 0
                features['has_suspicious_tld'] = 0
            
            url_lower = url.lower()
            features['has_at_symbol'] = 1 if '@' in url else 0
            
            keyword_count = 0
            for keyword in self.suspicious_keywords:
                if keyword in url_lower:
                    keyword_count += 1
            features['suspicious_keyword_count'] = keyword_count
            
            features['num_digits'] = sum(c.isdigit() for c in url)
            
            return features

# Test
extractor = URLFeatureExtractor()
test_urls = [
    'https://www.google.com',
    'http://secure-login.tk',
    'http://192.168.1.1:8080'
]

print("\nTesting feature extraction:")
for url in test_urls:
    features = extractor.extract(url)
    print(f"\nURL: {url}")
    for key, value in features.items():
        print(f"  {key}: {value}")

print("\n✅ Feature extraction working!")
