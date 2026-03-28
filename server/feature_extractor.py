import re
from urllib.parse import urlparse
from math import log2
from functools import lru_cache

# Pre-compile regex patterns
IP_PATTERN = re.compile(r'^\d+\.\d+\.\d+\.\d+$')  # FIXED
CONSONANTS = set('bcdfghjklmnpqrstvwxyz')  # FIXED (added 'w')

@lru_cache(maxsize=1000)
def parse_url_cached(url):  # FIXED function name
    """Cache URL parsing results"""
    return urlparse(url)

class FastFeatureExtractor:
    def __init__(self):  # FIXED indentation
        self.suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'click', 'loan', 'work', 'top', 'xyz', 'club'}
        self.short_services = {'bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly'}
        self.suspicious_ext = {'exe', 'scr', 'zip', 'rar', 'doc', 'docx', 'xls', 'xlsx'}
        self.keywords = {'secure', 'login', 'signin', 'verify', 'account', 'update', 
                        'confirm', 'banking', 'paypal', 'apple', 'microsoft', 'amazon'}
    
    def extract(self, url):
        """Fast feature extraction"""
        url_str = url.lower()
        
        # Parse URL (cached)
        parsed = parse_url_cached(url_str)
        domain = parsed.netloc.split(':')[0]
        subdomains = domain.split('.')
        tld = subdomains[-1] if subdomains else ''
        path = parsed.path.lower()
        
        # Fast character counts
        digit_count = sum(1 for c in url_str if c.isdigit())
        letter_count = sum(1 for c in url_str if c.isalpha())
        special_chars = sum(1 for c in url_str if not c.isalnum())
        
        # Fast keyword count
        keyword_count = 0
        for k in self.keywords:
            if k in url_str:
                keyword_count += 1
        
        # Fast consecutive consonants
        max_cons = 0
        current = 0
        for c in url_str:
            if c in CONSONANTS:
                current += 1
                if current > max_cons:
                    max_cons = current
            else:
                current = 0
        
        # Fast entropy calculation
        def calc_entropy(s):
            if not s:
                return 0
            prob = [s.count(c)/len(s) for c in set(s)]
            return -sum(p * log2(p) for p in prob if p > 0)
        
        return {
            'URLLength': len(url_str),
            'IsHTTPS': 1 if url_str.startswith('https') else 0,
            'DomainLength': len(domain),
            'IsDomainIP': 1 if IP_PATTERN.match(domain) else 0,
            'NoOfSubDomain': max(0, len(subdomains) - 2),
            'HasDeepSubdomain': 1 if len(subdomains) > 3 else 0,
            'TLDLength': len(tld),
            'HasSuspiciousTLD': 1 if tld in self.suspicious_tlds else 0,
            'IsShortenedURL': 1 if any(s in domain for s in self.short_services) else 0,
            'HasObfuscation': 1 if '@' in url_str or '//' in url_str[8:] else 0,
            'NoOfObfuscatedChar': url_str.count('@') + url_str.count('%') + url_str.count('//'),
            'HasAtSymbol': 1 if '@' in url_str else 0,
            'HasDoubleSlash': 1 if '//' in url_str[8:] else 0,
            'NoOfLettersInURL': letter_count,
            'NoOfDigitsInURL': digit_count,
            'LetterToDigitRatio': digit_count / max(1, letter_count),
            'SpecialCharRatio': special_chars / max(1, len(url_str)),
            'NoOfEqualsInURL': url_str.count('='),
            'NoOfQMarkInURL': url_str.count('?'),
            'NoOfAmpersandInURL': url_str.count('&'),
            'HasPort': 1 if ':' in domain else 0,
            'HasSuspiciousFileExt': 1 if any(path.endswith(ext) for ext in self.suspicious_ext) else 0,
            'SuspiciousKeywordCount': keyword_count,
            'DigitConcentration': digit_count / max(1, len(url_str)),
            'Entropy': calc_entropy(url_str),
            'MaxConsecutiveConsonants': max_cons,
            'PathLength': len(path),
            'QueryLength': len(parsed.query),
            'HasFragment': 1 if parsed.fragment else 0,
            'URLDepth': path.count('/')
        }