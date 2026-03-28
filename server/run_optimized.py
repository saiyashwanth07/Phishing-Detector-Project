from waitress import serve
import native_api
import time

print("="*60)
print("🚀 OPTIMIZED PRODUCTION SERVER")
print("="*60)

# Add latency logging middleware
class LatencyMiddleware:
    def __init__(self, app):
        self.app = app
    
    def __call__(self, environ, start_response):
        start = time.time()
        response = self.app(environ, start_response)
        end = time.time()
        print(f"⏱️  Request latency: {(end-start)*1000:.2f}ms")
        return response

# Wrap app with middleware
native_api.app.wsgi_app = LatencyMiddleware(native_api.app.wsgi_app)

# Serve with optimized settings
serve(
    native_api.app,
    host='0.0.0.0',
    port=5000,
    threads=8,              # Handle 8 requests in parallel
    connection_limit=1000,   # Max connections
    channel_timeout=30,      # Timeout in seconds
    cleanup_interval=10      # Clean up idle connections
)