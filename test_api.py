import requests
import json

def test_api():
    """Test the API endpoints"""
    base_url = "http://localhost:5000"
    
    print("="*60)
    print("Testing PhiUSIIL API")
    print("="*60)
    
    # Test health
    print("\n1. Testing health endpoint...")
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            health = response.json()
            print(f"✅ Health: {health.get('status')}")
            print(f"   Model loaded: {health.get('model_loaded')}")
            print(f"   Accuracy: {health.get('accuracy', 'N/A')}")
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return
    except:
        print("❌ Cannot connect to API server")
        print("   Make sure to run: python server/native_api.py")
        return
    
    # Test predictions
    print("\n2. Testing predictions...")
    test_urls = [
        ("https://www.google.com", "should be legitimate"),
        ("http://secure-login.tk", "should be phishing (suspicious TLD)"),
        ("http://192.168.1.1:8080", "should be phishing (IP address)"),
        ("https://github.com", "should be legitimate"),
        ("https://apple-id-confirm.ga", "should be phishing"),
    ]
    
    for url, note in test_urls:
        print(f"\n   Testing: {url}")
        print(f"   Note: {note}")
        
        try:
            response = requests.post(
                f"{base_url}/predict",
                json={"url": url},
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"   ✅ {result.get('prediction', 'unknown').upper()}")
                print(f"   Confidence: {result.get('confidence', 0)}%")
                
                if 'reasons' in result and result['reasons']:
                    print(f"   Reasons: {', '.join(result['reasons'])}")
            else:
                print(f"   ❌ Error: {response.status_code}")
                print(f"   {response.text}")
                
        except Exception as e:
            print(f"   ❌ Request failed: {e}")
    
    # Test feature extraction
    print("\n3. Testing feature extraction...")
    try:
        response = requests.post(
            f"{base_url}/features",
            json={"url": "https://www.example.com"},
            timeout=5
        )
        if response.status_code == 200:
            result = response.json()
            print(f"   ✅ Features extracted: {result.get('count', 0)}")
        else:
            print(f"   ❌ Failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Failed: {e}")
    
    print("\n" + "="*60)
    print("API Test Complete")
    print("="*60)
    print("\n🎯 To use with Chrome extension:")
    print("1. Keep API server running")
    print("2. Load extension in Chrome")
    print("3. Visit test URLs to see real-time detection")

if __name__ == '__main__':
    test_api()