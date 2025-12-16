#!/usr/bin/env python3
"""
Test script for ESP32 Portal Token API pagination
Demonstrates how to fetch all unused tokens using the new pagination feature
"""

import requests
import time
import sys

def get_all_unused_tokens(base_url, api_key, max_pages=10):
    """
    Fetch all unused tokens using pagination
    Returns list of all unused tokens
    """
    all_tokens = []
    offset = 0
    limit = 100  # Max per page
    page = 0

    print(f"Fetching unused tokens from {base_url}...")

    while page < max_pages:
        params = {
            "api_key": api_key,
            "status": "unused",  # Only unused tokens
            "offset": offset,
            "limit": limit
        }

        try:
            response = requests.get(f"{base_url}/api/tokens/list", params=params, timeout=10)
            response.raise_for_status()
            data = response.json()

            if not data.get("success", False):
                print(f"API error: {data}")
                return None

            tokens = data.get("tokens", [])
            all_tokens.extend(tokens)

            total_count = data.get("total_count", 0)
            returned_count = data.get("returned_count", 0)
            has_more = data.get("has_more", False)

            print(f"Page {page + 1}: Got {returned_count} tokens (total so far: {len(all_tokens)}/{total_count})")

            if not has_more:
                break

            offset += limit
            page += 1

            # Small delay to be nice to the device
            time.sleep(0.1)

        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None

    return all_tokens

def main():
    if len(sys.argv) != 3:
        print("Usage: python test_pagination.py <base_url> <api_key>")
        print("Example: python test_pagination.py http://192.168.0.100 abcd1234efgh5678ijkl9012mnop3456")
        sys.exit(1)

    base_url = sys.argv[1].rstrip('/')
    api_key = sys.argv[2]

    print("Testing ESP32 Portal Token API pagination...")
    print(f"Base URL: {base_url}")
    print(f"API Key: {api_key[:8]}...")
    print()

    # Test single page first
    print("Testing single page request...")
    params = {
        "api_key": api_key,
        "status": "unused",
        "limit": 10  # Small limit for testing
    }

    try:
        response = requests.get(f"{base_url}/api/tokens/list", params=params, timeout=5)
        response.raise_for_status()
        data = response.json()

        print(f"Single page response: success={data.get('success')}")
        print(f"Total count: {data.get('total_count')}")
        print(f"Returned count: {data.get('returned_count')}")
        print(f"Has more: {data.get('has_more')}")
        print(f"Tokens in response: {len(data.get('tokens', []))}")
        print()

    except requests.exceptions.RequestException as e:
        print(f"Single page test failed: {e}")
        return

    # Test fetching all unused tokens
    print("Testing pagination - fetching all unused tokens...")
    unused_tokens = get_all_unused_tokens(base_url, api_key)

    if unused_tokens is not None:
        print(f"\nSuccess! Retrieved {len(unused_tokens)} unused tokens")
        if unused_tokens:
            print("Sample tokens:")
            for i, token in enumerate(unused_tokens[:3]):  # Show first 3
                print(f"  {token['token']} - created {time.ctime(token['first_use'] or token.get('created', 0))}")
            if len(unused_tokens) > 3:
                print(f"  ... and {len(unused_tokens) - 3} more")
    else:
        print("Failed to retrieve tokens")

if __name__ == "__main__":
    main()