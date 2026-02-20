import pandas as pd
import numpy as np
import random
import re

def generate_realistic_dataset():
    """Create realistic phishing/legitimate dataset"""
    data = []
    
    # ===== REALISTIC LEGITIMATE URL PATTERNS =====
    legitimate_patterns = [
        # Major websites (always HTTPS)
        'https://www.google.com/search?q={query}',
        'https://github.com/{user}/{repo}',
        'https://stackoverflow.com/questions/{id}',
        'https://www.amazon.com/dp/{product_id}',
        'https://www.youtube.com/watch?v={video_id}',
        'https://www.wikipedia.org/wiki/{topic}',
        'https://www.reddit.com/r/{subreddit}',
        'https://www.linkedin.com/in/{name}',
        
        # Company websites (mix of HTTP/HTTPS)
        'http://www.{company}.com',
        'https://{company}.org',
        'http://blog.{company}.net',
        
        # Educational
        'https://{university}.edu',
        'http://www.{school}.ac.{country}',
        
        # Government
        'https://www.{gov}.gov',
        'http://{department}.{state}.gov',
    ]
    
    # ===== REALISTIC PHISHING URL PATTERNS =====
    phishing_patterns = [
        # Suspicious TLDs (common in phishing)
        'http://secure-login.tk',
        'https://account-update.ml',
        'http://paypal-confirm.ga',
        'https://apple-verify.cf',
        'http://bank-update.xyz',
        
        # IP addresses
        'http://192.168.1.{num}:8080',
        'https://10.0.0.{num}/admin',
        'http://{ip}/login.aspx',
        
        # @ symbol attacks
        'https://google.com@evil.tk',
        'http://paypal.com@phish.ga',
        
        # Brand impersonation
        'http://{brand}-secure-login.com',
        'https://{brand}-account-verify.net',
        'http://update-{brand}-password.org',
        
        # Shortened URLs
        'https://bit.ly/{random}',
        'http://tinyurl.com/{random}',
        
        # Many parameters
        'http://verify.tk?id={num}&session={hex}&token={hex}',
        'https://update.ga?user={name}&pass={random}&confirm=1',
    ]
    
    brands = ['paypal', 'apple', 'microsoft', 'amazon', 'ebay', 'google', 'facebook']
    companies = ['acme', 'techcorp', 'global', 'innovate', 'solution', 'enterprise']
    countries = ['uk', 'us', 'ca', 'au', 'in']
    
    print("Generating realistic dataset...")
    
    # Generate legitimate URLs
    for _ in range(5000):
        pattern = random.choice(legitimate_patterns)
        
        # Fill placeholders
        url = pattern
        url = url.replace('{query}', random.choice(['python', 'machine+learning', 'tutorial', 'news']))
        url = url.replace('{user}', random.choice(['john', 'jane', 'dev', 'admin']))
        url = url.replace('{repo}', random.choice(['project', 'code', 'library', 'app']))
        url = url.replace('{id}', str(random.randint(10000, 99999)))
        url = url.replace('{product_id}', 'B0' + ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=8)))
        url = url.replace('{video_id}', ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_', k=11)))
        url = url.replace('{topic}', random.choice(['Artificial_intelligence', 'Computer_science', 'Mathematics', 'History']))
        url = url.replace('{subreddit}', random.choice(['programming', 'technology', 'science', 'worldnews']))
        url = url.replace('{name}', random.choice(['johndoe', 'janedoe', 'alexsmith', 'sarahjones']))
        url = url.replace('{company}', random.choice(companies))
        url = url.replace('{university}', random.choice(['harvard', 'stanford', 'mit', 'oxford']))
        url = url.replace('{school}', random.choice(['highschool', 'middleschool', 'elementary']))
        url = url.replace('{country}', random.choice(countries))
        url = url.replace('{gov}', random.choice(['whitehouse', 'parliament', 'congress']))
        url = url.replace('{department}', random.choice(['health', 'education', 'transport']))
        url = url.replace('{state}', random.choice(['california', 'texas', 'newyork', 'florida']))
        
        data.append({'URL': url, 'label': 0})
    
    # Generate phishing URLs
    for _ in range(5000):
        pattern = random.choice(phishing_patterns)
        
        url = pattern
        url = url.replace('{num}', str(random.randint(1, 255)))
        url = url.replace('{random}', ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=6)))
        url = url.replace('{hex}', ''.join(random.choices('abcdef0123456789', k=16)))
        url = url.replace('{name}', random.choice(['admin', 'user', 'customer', 'member']))
        url = url.replace('{brand}', random.choice(brands))
        url = url.replace('{ip}', f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}")
        
        data.append({'URL': url, 'label': 1})
    
    # Create DataFrame
    df = pd.DataFrame(data)
    
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print(f"Created dataset: {len(df)} URLs")
    print(f"  Legitimate: {sum(df['label'] == 0)}")
    print(f"  Phishing: {sum(df['label'] == 1)}")
    
    # Save
    df.to_csv('realistic_dataset.csv', index=False)
    print("✅ Saved: realistic_dataset.csv")
    
    # Show samples
    print("\nSample legitimate URLs:")
    for url in df[df['label'] == 0]['URL'].head(3):
        print(f"  {url}")
    
    print("\nSample phishing URLs:")
    for url in df[df['label'] == 1]['URL'].head(3):
        print(f"  {url}")
    
    return df

if __name__ == '__main__':
    generate_realistic_dataset()