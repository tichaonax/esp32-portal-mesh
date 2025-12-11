"""
Pytest Configuration and Fixtures

Shared fixtures and configuration for all test modules.
"""

import pytest
import requests
import time
from typing import Generator, Dict, Any
from .config import TestConfig


def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "monitoring: tests for monitoring endpoints (no auth required)"
    )
    config.addinivalue_line(
        "markers", "token_mgmt: tests for token management endpoints (auth required)"
    )
    config.addinivalue_line(
        "markers", "integration: end-to-end integration tests"
    )
    config.addinivalue_line(
        "markers", "error: error scenario tests"
    )
    config.addinivalue_line(
        "markers", "stress: stress and load tests"
    )
    config.addinivalue_line(
        "markers", "timing: time-sensitive tests"
    )
    config.addinivalue_line(
        "markers", "regression: regression tests for past bugs"
    )
    config.addinivalue_line(
        "markers", "edge_case: edge case and boundary tests"
    )


# Track last test class to add delay between test classes
_last_test_class = [None]


def pytest_runtest_setup(item):
    """
    Hook called before each test runs.
    Add a small delay between test classes to give device time to process.
    """
    current_class = item.cls.__name__ if item.cls else None
    
    if current_class and current_class != _last_test_class[0]:
        if _last_test_class[0] is not None:
            # Switching test classes - add delay
            time.sleep(0.25)  # 250ms between test classes
        _last_test_class[0] = current_class


@pytest.fixture(scope="session", autouse=True)
def verify_api_key():
    """Verify API key is available before running tests"""
    test_config = TestConfig()
    if not test_config.API_KEY:
        print("\n" + "="*60)
        print("ESP32 API Key Required")
        print("="*60)
        print("Please obtain the API key from the admin dashboard:")
        print(f"1. Navigate to http://192.168.4.1/admin")
        print(f"2. Login with admin credentials")
        print(f"3. Copy the API key from the dashboard")
        print("\nOr set the environment variable:")
        print("export ESP32_API_KEY='your-32-character-key'")
        print("="*60)
        
        api_key = input("\nEnter API Key: ").strip()
        if not api_key:
            pytest.exit("API Key is required to run tests", returncode=1)
        
        test_config.API_KEY = api_key
        print(f"✓ API Key configured")


@pytest.fixture(scope="session")
def test_config():
    """Provide test configuration to all tests"""
    return TestConfig()


@pytest.fixture(scope="session")
def base_url(test_config):
    """Base URL for API requests"""
    return test_config.BASE_URL


@pytest.fixture
def session(test_config) -> Generator[requests.Session, None, None]:
    """
    HTTP session with timeout configured and request throttling.
    
    Adds a small delay between requests to simulate realistic usage
    and prevent overwhelming the ESP32 device.
    """
    session = requests.Session()
    session.timeout = test_config.REQUEST_TIMEOUT
    
    # Monkey-patch the request method to add throttling
    original_request = session.request
    last_request_time = [0]  # Use list to allow modification in closure
    
    def throttled_request(*args, **kwargs):
        # Wait at least 100ms between requests to simulate real-world usage
        elapsed = time.time() - last_request_time[0]
        if elapsed < 0.1:  # 100ms minimum between requests
            time.sleep(0.1 - elapsed)
        
        result = original_request(*args, **kwargs)
        last_request_time[0] = time.time()
        return result
    
    session.request = throttled_request
    
    yield session
    session.close()


@pytest.fixture
def api_headers() -> Dict[str, str]:
    """Common headers for API requests"""
    return {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "ESP32-Portal-Test-Suite/1.0"
    }


@pytest.fixture
def test_token(test_config, base_url, session) -> Generator[str, None, None]:
    """
    Create a test token and clean it up after the test.
    
    Yields:
        str: The created token string
    """
    # Create token
    response = session.post(
        f"{base_url}/api/token",
        data={
            "api_key": test_config.API_KEY,
            "duration": test_config.TEST_TOKEN_DURATION,
            "bandwidth_down": test_config.TEST_BANDWIDTH_DOWN,
            "bandwidth_up": test_config.TEST_BANDWIDTH_UP
        }
    )
    
    if not response.ok:
        pytest.fail(f"Failed to create test token: {response.status_code} - {response.text}")
    
    token = response.json()["token"]
    print(f"\n✓ Created test token: {token}")
    
    yield token
    
    # Cleanup: disable token after test
    if test_config.CLEANUP_TEST_TOKENS:
        try:
            cleanup_response = session.post(
                f"{base_url}/api/token/disable",
                data={"api_key": test_config.API_KEY, "token": token}
            )
            if cleanup_response.ok:
                print(f"✓ Cleaned up test token: {token}")
            else:
                print(f"⚠ Failed to cleanup token {token}: {cleanup_response.status_code}")
        except Exception as e:
            print(f"⚠ Error during token cleanup: {e}")


@pytest.fixture
def multiple_test_tokens(test_config, base_url, session, request) -> Generator[list, None, None]:
    """
    Create multiple test tokens and clean them up after the test.
    
    Usage:
        @pytest.mark.parametrize("token_count", [3], indirect=True)
        def test_something(multiple_test_tokens):
            tokens = multiple_test_tokens  # List of token strings
    
    Args:
        request: Pytest request object with param for count
    
    Yields:
        list: List of created token strings
    """
    count = getattr(request, 'param', 3)  # Default to 3 tokens
    tokens = []
    
    for i in range(count):
        # Add small delay between token creations to avoid overwhelming device
        if i > 0:
            time.sleep(0.15)  # 150ms between token creations
        
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.TEST_TOKEN_DURATION + (i * 10),  # Vary duration
                "bandwidth_down": test_config.TEST_BANDWIDTH_DOWN,
                "bandwidth_up": test_config.TEST_BANDWIDTH_UP
            }
        )
        
        if response.ok:
            token = response.json()["token"]
            tokens.append(token)
            print(f"✓ Created test token {i+1}/{count}: {token}")
        else:
            pytest.fail(f"Failed to create token {i+1}: {response.status_code}")
    
    yield tokens
    
    # Cleanup all tokens
    if test_config.CLEANUP_TEST_TOKENS:
        for i, token in enumerate(tokens):
            try:
                # Add delay between cleanup operations
                if i > 0:
                    time.sleep(0.1)  # 100ms between cleanups
                
                session.post(
                    f"{base_url}/api/token/disable",
                    data={"api_key": test_config.API_KEY, "token": token}
                )
            except:
                pass  # Best effort cleanup


@pytest.fixture(scope="session")
def initial_device_health(base_url) -> Dict[str, Any]:
    """
    Get initial device health for baseline comparison.
    
    Returns:
        dict: Initial health status or None if unavailable
    """
    try:
        response = requests.get(f"{base_url}/api/health", timeout=5)
        if response.ok:
            health = response.json()
            print(f"\n📊 Initial Device Health:")
            print(f"  - Uptime: {health['uptime_seconds']}s")
            print(f"  - Active Tokens: {health['active_tokens']}/{health['max_tokens']}")
            print(f"  - Free Heap: {health['free_heap_bytes']:,} bytes")
            print(f"  - Time Synced: {health['time_synced']}")
            return health
    except Exception as e:
        print(f"⚠ Could not get initial health: {e}")
    
    return None


@pytest.fixture
def wait_for_cleanup():
    """
    Wait for automatic token cleanup cycle (30 seconds).
    Use this when testing cleanup behavior.
    """
    def _wait(seconds: int = 31):
        print(f"\n⏳ Waiting {seconds}s for cleanup cycle...")
        time.sleep(seconds)
        print("✓ Cleanup cycle should have completed")
    
    return _wait


# Utility functions available to all tests

def assert_valid_token_format(token: str):
    """Assert token has valid format (8 uppercase alphanumeric characters)"""
    assert isinstance(token, str), "Token must be a string"
    assert len(token) == 8, f"Token must be 8 characters, got {len(token)}"
    assert token.isupper(), "Token must be uppercase"
    assert token.isalnum(), "Token must be alphanumeric"


def assert_valid_timestamp(timestamp: int):
    """Assert timestamp is a valid Unix timestamp"""
    assert isinstance(timestamp, int), "Timestamp must be an integer"
    assert timestamp > 1609459200, "Timestamp must be after 2021-01-01"  # Sanity check
    assert timestamp < 2000000000, "Timestamp must be before 2033-05-18"  # Sanity check


def assert_response_time(response: requests.Response, max_time: float = 1.0):
    """Assert API response time is acceptable"""
    elapsed = response.elapsed.total_seconds()
    assert elapsed < max_time, f"Response took {elapsed:.2f}s (max: {max_time}s)"
