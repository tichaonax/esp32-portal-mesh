#!/usr/bin/env python3
"""
Test concurrent HTTP requests to ESP32 to verify non-blocking behavior
"""
import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

ESP32_IP = "http://192.168.0.120"
NUM_CONCURRENT_REQUESTS = 10

def test_endpoint(endpoint, request_id, delay=0):
    """Make a request to an endpoint and measure response time"""
    start_time = time.time()
    try:
        if delay > 0:
            time.sleep(delay)

        print(f"[Request {request_id}] Starting request to {endpoint}")
        response = requests.get(f"{ESP32_IP}{endpoint}", timeout=15)
        elapsed = time.time() - start_time

        print(f"[Request {request_id}] ✓ SUCCESS: {endpoint} - Status: {response.status_code}, Time: {elapsed:.2f}s")
        return {
            'request_id': request_id,
            'endpoint': endpoint,
            'status_code': response.status_code,
            'elapsed': elapsed,
            'success': True
        }
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"[Request {request_id}] ✗ FAILED: {endpoint} - Error: {str(e)}, Time: {elapsed:.2f}s")
        return {
            'request_id': request_id,
            'endpoint': endpoint,
            'status_code': None,
            'elapsed': elapsed,
            'success': False,
            'error': str(e)
        }

def test_concurrent_same_endpoint():
    """Test multiple concurrent requests to the same endpoint"""
    print("\n" + "="*80)
    print("TEST 1: Multiple concurrent requests to the same endpoint (/)")
    print("="*80)

    start_time = time.time()
    with ThreadPoolExecutor(max_workers=NUM_CONCURRENT_REQUESTS) as executor:
        futures = [
            executor.submit(test_endpoint, "/", i)
            for i in range(NUM_CONCURRENT_REQUESTS)
        ]

        results = [future.result() for future in as_completed(futures)]

    total_time = time.time() - start_time
    successful = sum(1 for r in results if r['success'])

    print(f"\nResults: {successful}/{NUM_CONCURRENT_REQUESTS} successful in {total_time:.2f}s")
    return successful == NUM_CONCURRENT_REQUESTS

def test_concurrent_different_endpoints():
    """Test concurrent requests to different endpoints"""
    print("\n" + "="*80)
    print("TEST 2: Concurrent requests to different endpoints")
    print("="*80)

    endpoints = [
        "/",
        "/api/tokens",
        "/admin",
        "/api/sessions",
        "/api/ap/info",
    ]

    start_time = time.time()
    with ThreadPoolExecutor(max_workers=len(endpoints)) as executor:
        futures = [
            executor.submit(test_endpoint, endpoint, i)
            for i, endpoint in enumerate(endpoints)
        ]

        results = [future.result() for future in as_completed(futures)]

    total_time = time.time() - start_time
    successful = sum(1 for r in results if r['success'])

    print(f"\nResults: {successful}/{len(endpoints)} successful in {total_time:.2f}s")
    return successful == len(endpoints)

def test_rapid_fire():
    """Test rapid-fire requests with minimal delay"""
    print("\n" + "="*80)
    print("TEST 3: Rapid-fire requests (testing listen backlog)")
    print("="*80)

    num_requests = 8
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=num_requests) as executor:
        futures = [
            executor.submit(test_endpoint, "/", i, delay=i*0.1)
            for i in range(num_requests)
        ]

        results = [future.result() for future in as_completed(futures)]

    total_time = time.time() - start_time
    successful = sum(1 for r in results if r['success'])

    print(f"\nResults: {successful}/{num_requests} successful in {total_time:.2f}s")
    return successful == num_requests

def test_token_operations_concurrent():
    """Test that token list requests work concurrently"""
    print("\n" + "="*80)
    print("TEST 4: Concurrent token list requests (tests NVS mutex timeout)")
    print("="*80)

    num_requests = 5
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=num_requests) as executor:
        futures = [
            executor.submit(test_endpoint, "/api/tokens", i)
            for i in range(num_requests)
        ]

        results = [future.result() for future in as_completed(futures)]

    total_time = time.time() - start_time
    successful = sum(1 for r in results if r['success'])

    print(f"\nResults: {successful}/{num_requests} successful in {total_time:.2f}s")
    print(f"Average response time: {sum(r['elapsed'] for r in results if r['success'])/successful:.2f}s")
    return successful == num_requests

def main():
    print(f"Testing ESP32 at {ESP32_IP}")
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # First, check if ESP32 is reachable
    print("\nChecking connectivity...")
    try:
        response = requests.get(f"{ESP32_IP}/", timeout=5)
        print(f"✓ ESP32 is reachable (Status: {response.status_code})")
    except Exception as e:
        print(f"✗ Cannot reach ESP32: {e}")
        return

    # Run tests
    results = []
    results.append(("Concurrent same endpoint", test_concurrent_same_endpoint()))
    results.append(("Concurrent different endpoints", test_concurrent_different_endpoints()))
    results.append(("Rapid-fire requests", test_rapid_fire()))
    results.append(("Token operations concurrent", test_token_operations_concurrent()))

    # Summary
    print("\n" + "="*80)
    print("FINAL SUMMARY")
    print("="*80)
    for test_name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {test_name}")

    total_passed = sum(1 for _, passed in results if passed)
    print(f"\nTotal: {total_passed}/{len(results)} tests passed")

    if total_passed == len(results):
        print("\n✓ All tests passed! The blocking issues have been fixed.")
    else:
        print("\n✗ Some tests failed. There may still be blocking issues.")

if __name__ == "__main__":
    main()
