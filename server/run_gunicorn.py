from waitress import serve
import native_api  # This should work if files are in same folder

print("="*60)
print("🚀 PRODUCTION SERVER - OPTIMIZED")
print("="*60)

serve(
    native_api.app, 
    host='0.0.0.0', 
    port=5000, 
    threads=8,
    connection_limit=1000,
    channel_timeout=30
)