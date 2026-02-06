"""
Demo Python Application for Kloak - Host Restriction Demo

This app demonstrates the host restriction feature by using TWO secrets:
1. secret-allowed: Configured with getkloak.io/hosts=httpbin.org (will be replaced)
2. secret-blocked: Configured with getkloak.io/hosts=example.com (will NOT be replaced)

When making requests to httpbin.org:
- X-Secret-Allowed header will show the ORIGINAL value (replaced by Kloak)
- X-Secret-Blocked header will show the UUID (NOT replaced, wrong host)
"""

import os
import time
import requests


def load_secret(file_env_var, default_value):
    """Load a secret from a file path specified in an environment variable."""
    file_path = os.getenv(file_env_var)
    if file_path and os.path.exists(file_path):
        with open(file_path, 'r') as f:
            value = f.read().strip()
        print(f"Loaded secret from {file_path}")
        return value
    return default_value


def main():
    # Load two secrets with different host restrictions
    # Secret 1: Allowed for httpbin.org
    key_allowed = load_secret("SECRET_ALLOWED_FILE", "allowed-default-key")
    # Secret 2: Blocked for httpbin.org (only allowed for example.com)
    key_blocked = load_secret("SECRET_BLOCKED_FILE", "blocked-default-key")

    target_url = os.getenv("TARGET_URL", "https://httpbin.org/headers")

    print("=" * 60)
    print("Kloak Demo: Host Restriction Feature")
    print("=" * 60)
    print(f"Target URL: {target_url}")
    print()
    print("Secrets (as seen by the app - these are UUIDs if Kloak is working):")
    print(f"  Secret Allowed (httpbin.org): {key_allowed[:30]}...")
    print(f"  Secret Blocked (example.com): {key_blocked[:30]}...")
    print()
    print("Expected behavior:")
    print("  - X-Secret-Allowed: Should show ORIGINAL value in response")
    print("  - X-Secret-Blocked: Should show UUID in response (not replaced)")
    print("=" * 60)

    # Check for Kloak CA
    ca_path = os.getenv("SSL_CERT_FILE")
    if ca_path and os.path.exists(ca_path):
        print(f"✓ Kloak CA found at {ca_path}")
        verify = ca_path
    else:
        print("✗ Kloak CA not found, using system CAs")
        verify = True

    # Make requests in a loop
    request_count = 0
    while True:
        request_count += 1
        print(f"\n--- Request #{request_count} ---")

        try:
            headers = {
                "X-Secret-Allowed": key_allowed,
                "X-Secret-Blocked": key_blocked,
                "Authorization": f"Bearer {key_allowed}",
            }

            response = requests.get(
                target_url,
                headers=headers,
                verify=verify,
                timeout=10
            )

            print(f"Status: {response.status_code}")
            print("Response headers echoed back by httpbin:")
            print(response.text[:800])

        except requests.exceptions.SSLError as e:
            print(f"SSL Error: {e}")
        except Exception as e:
            print(f"Error: {e}")

        interval = int(os.getenv("REQUEST_INTERVAL", "10"))
        print(f"\nWaiting {interval}s before next request...")
        time.sleep(interval)


if __name__ == "__main__":
    main()
