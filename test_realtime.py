import requests
import time

print("="*60)
print("REAL-TIME LATENCY TEST")
print("="*60)

url = "https://www.google.com"

# Test 1: Direct timing of the request
print(f"\n📊 Testing URL: {url}")

start = time.perf_counter()
response = requests.post("http://localhost:5000/predict", json={"url": url})
end = time.perf_counter()

client_time = (end - start) * 1000
server_time = response.elapsed.total_seconds() * 1000

print(f"\n✅ Client measured: {client_time:.2f}ms")
print(f"✅ Server reported: {server_time:.2f}ms")
print(f"📊 Difference: {client_time - server_time:.2f}ms (network overhead)")

# Test 2: Multiple requests to see pattern
print("\n📊 Testing 5 requests in sequence...")
times = []
for i in range(5):
    start = time.perf_counter()
    response = requests.post("http://localhost:5000/predict", json={"url": url})
    end = time.perf_counter()
    times.append((end - start) * 1000)
    print(f"   Request {i+1}: {times[-1]:.2f}ms")

print(f"\n📈 Average: {sum(times)/len(times):.2f}ms")

print("\n" + "="*60)