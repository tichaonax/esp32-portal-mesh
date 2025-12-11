"""
Test Configuration

Configuration settings for ESP32 Portal API integration tests.
"""

import os
from dataclasses import dataclass


@dataclass
class TestConfig:
    """Test configuration settings"""
    
    # Device configuration
    DEVICE_IP: str = "192.168.0.120"
    BASE_URL: str = f"http://{DEVICE_IP}"
    
    # API Key (loaded from environment or will be prompted)
    API_KEY: str = os.getenv("ESP32_API_KEY", "")
    
    # Test parameters
    TEST_TOKEN_DURATION: int = 30  # minutes (minimum allowed)
    TEST_BANDWIDTH_DOWN: int = 100  # MB
    TEST_BANDWIDTH_UP: int = 50    # MB
    
    # Token limits
    MIN_TOKEN_DURATION: int = 30      # minutes
    MAX_TOKEN_DURATION: int = 43200   # minutes (30 days)
    MIN_TOKEN_EXTENSION: int = 30     # minutes
    MAX_TOKEN_EXTENSION: int = 10080  # minutes (7 days)
    
    # Timeouts and retries
    REQUEST_TIMEOUT: int = 5  # seconds
    RETRY_ATTEMPTS: int = 3
    RETRY_DELAY: int = 1  # seconds
    
    # Health thresholds
    MIN_FREE_HEAP: int = 50000   # bytes (50 KB minimum)
    MAX_ACTIVE_TOKENS: int = 230
    MAX_DEVICES_PER_TOKEN: int = 2
    
    # Test behavior
    CLEANUP_TEST_TOKENS: bool = True
    VERBOSE_LOGGING: bool = True
    
    def __post_init__(self):
        """Validate configuration after initialization"""
        if not self.DEVICE_IP:
            raise ValueError("DEVICE_IP must be set")
        
        if not self.BASE_URL.startswith("http"):
            raise ValueError("BASE_URL must start with http:// or https://")


# Global configuration instance
config = TestConfig()
