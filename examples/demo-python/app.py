"""
Demo Python Application for Bouncer

This app makes HTTPS requests using the 'requests' library.
When Bouncer is enabled, the Root CA is mounted and traffic
is transparently proxied through the Envoy sidecar.
"""

import os
import sys
import time
import requests

def main():
    # API key from environment (will be hashed by Bouncer webhook)
    api_key = os.getenv("API_KEY", "demo-api-key-12345")
    
    # Target URL (can be overridden)
    target_url = os.getenv("TARGET_URL", "https://httpbin.org/headers")
    
    print(f"Bouncer Demo Application")
    print(f"========================")
    print(f"Target URL: {target_url}")
    print(f"API Key (first 10 chars): {api_key[:10]}...")
    print()
    
    # Check if Bouncer CA is mounted
    ca_path = "/etc/ssl/certs/bouncer-ca.crt"
    if os.path.exists(ca_path):
        print(f"✓ Bouncer CA found at {ca_path}")
        # Use the custom CA for verification
        verify = ca_path
    else:
        print(f"✗ Bouncer CA not found, using system CAs")
        verify = True
    
    # Make requests in a loop
    request_count = 0
    while True:
        request_count += 1
        print(f"\n--- Request #{request_count} ---")
        
        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "X-Custom-Header": "bouncer-test",
            }
            
            response = requests.get(
                target_url,
                headers=headers,
                verify=verify,
                timeout=10
            )
            
            print(f"Status: {response.status_code}")
            print(f"Response (first 500 chars):")
            print(response.text[:500])
            
        except requests.exceptions.SSLError as e:
            print(f"SSL Error: {e}")
            print("This might indicate the Bouncer CA is not properly installed")
        except Exception as e:
            print(f"Error: {e}")
        
        # Wait before next request
        interval = int(os.getenv("REQUEST_INTERVAL", "10"))
        print(f"\nWaiting {interval}s before next request...")
        time.sleep(interval)

if __name__ == "__main__":
    main()
