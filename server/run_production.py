from waitress import serve
import native_api

print("="*60)
print("🚀 PRODUCTION SERVER - WAITRESS")
print("="*60)
print("📍 Running on: http://localhost:5000")
print("📌 Press Ctrl+C to stop")
print("="*60)

serve(native_api.app, host='0.0.0.0', port=5000, threads=4)