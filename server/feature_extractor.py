import re
import numpy as np
from urllib.parse import urlparse
import math

class SimpleFeatureExtractor:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'signin', 'verify', 'secure', 'account', 'banking',
            'update', 'confirm', 'password', 'wallet', 'paypal', 'ebay',
            'amazon', 'apple', 'microsoft', 'support', 'service', 'alert'
        ]
        
        self.suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top']
    
    def extract(self, url):
        """Simple feature extraction without tldextract"""
        features = {}
        
        # Basic URL features
        features['url_length'] = len(url)
        features['is_https'] = 1 if url.startswith('https') else 0
        
        # Domain analysis
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0] if parsed.netloc else ''
            
            features['domain_length'] = len(domain)
            
            # IP address check
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            features['is_ip_address'] = 1 if re.match(ip_pattern, domain) else 0
            
            # Subdomain count
            subdomain_count = domain.count('.') - 1
            features['num_subdomains'] = max(0, subdomain_count)
            
            # TLD check (simplified)
            parts = domain.split('.')
            if len(parts) >= 2:
                tld = parts[-1].lower()
                features['has_suspicious_tld'] = 1 if tld in self.suspicious_tlds else 0
            else:
                features['has_suspicious_tld'] = 0
            
            # Port check
            features['has_port'] = 1 if ':' in parsed.netloc else 0
            
        except:
            features['domain_length'] = 0
            features['is_ip_address'] = 0
            features['num_subdomains'] = 0
            features['has_suspicious_tld'] = 0
            features['has_port'] = 0
        
        # Character features
        url_lower = url.lower()
        features['has_at_symbol'] = 1 if '@' in url else 0
        features['has_obfuscation'] = 1 if '%' in url else 0
        
        # Suspicious keywords
        keyword_count = 0
        for keyword in self.suspicious_keywords:
            if keyword in url_lower:
                keyword_count += 1
        features['suspicious_keyword_count'] = keyword_count
        
        # Character counts
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_special_chars'] = sum(not c.isalnum() for c in url)
        
        # Query parameters
        features['num_equals'] = url.count('=')
        features['num_question_marks'] = url.count('?')
        
        # Simple entropy calculation
        if url:
            prob = [float(url.count(c)) / len(url) for c in set(url)]
            features['entropy'] = -sum(p * math.log2(p) for p in prob if p > 0)
        else:
            features['entropy'] = 0
        
        return features