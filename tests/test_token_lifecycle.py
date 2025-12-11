"""
Token Lifecycle Integration Tests

Tests for token creation, querying, and basic operations.
Tests: POST /api/token, GET /api/token/info
"""

import pytest
from .conftest import assert_valid_token_format, assert_valid_timestamp, assert_response_time


@pytest.mark.token_mgmt
class TestTokenCreation:
    """Tests for POST /api/token endpoint"""
    
    def test_create_token_basic(self, base_url, session, test_config):
        """Create a token with basic parameters"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.TEST_TOKEN_DURATION,
                "bandwidth_down": test_config.TEST_BANDWIDTH_DOWN,
                "bandwidth_up": test_config.TEST_BANDWIDTH_UP
            }
        )
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        assert_response_time(response)
        
        data = response.json()
        
        # Verify response structure
        assert data["success"] is True
        assert "token" in data
        assert data["duration_minutes"] == test_config.TEST_TOKEN_DURATION
        assert data["bandwidth_down_mb"] == test_config.TEST_BANDWIDTH_DOWN
        assert data["bandwidth_up_mb"] == test_config.TEST_BANDWIDTH_UP
        
        # Verify token format
        assert_valid_token_format(data["token"])
        
        # Cleanup
        session.post(
            f"{base_url}/api/token/disable",
            data={"api_key": test_config.API_KEY, "token": data["token"]}
        )
    
    def test_create_token_minimum_duration(self, base_url, session, test_config):
        """Create token with minimum allowed duration"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.MIN_TOKEN_DURATION,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["duration_minutes"] == test_config.MIN_TOKEN_DURATION
        
        # Cleanup
        session.post(
            f"{base_url}/api/token/disable",
            data={"api_key": test_config.API_KEY, "token": data["token"]}
        )
    
    def test_create_token_maximum_duration(self, base_url, session, test_config):
        """Create token with maximum allowed duration"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.MAX_TOKEN_DURATION,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["duration_minutes"] == test_config.MAX_TOKEN_DURATION
        
        # Cleanup
        session.post(
            f"{base_url}/api/token/disable",
            data={"api_key": test_config.API_KEY, "token": data["token"]}
        )
    
    def test_create_token_unlimited_bandwidth(self, base_url, session, test_config):
        """Create token with unlimited bandwidth (0 values)"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.TEST_TOKEN_DURATION,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["bandwidth_down_mb"] == 0
        assert data["bandwidth_up_mb"] == 0
        
        # Cleanup
        session.post(
            f"{base_url}/api/token/disable",
            data={"api_key": test_config.API_KEY, "token": data["token"]}
        )
    
    def test_create_token_without_bandwidth_params(self, base_url, session, test_config):
        """Create token without specifying bandwidth parameters"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.TEST_TOKEN_DURATION
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        # Should default to 0 (unlimited)
        assert data["bandwidth_down_mb"] == 0
        assert data["bandwidth_up_mb"] == 0
        
        # Cleanup
        session.post(
            f"{base_url}/api/token/disable",
            data={"api_key": test_config.API_KEY, "token": data["token"]}
        )
    
    def test_create_multiple_tokens(self, base_url, session, test_config):
        """Create multiple tokens sequentially"""
        tokens = []
        
        for i in range(3):
            response = session.post(
                f"{base_url}/api/token",
                data={
                    "api_key": test_config.API_KEY,
                    "duration": test_config.TEST_TOKEN_DURATION + (i * 10),
                    "bandwidth_down": 100 + (i * 50),
                    "bandwidth_up": 50 + (i * 25)
                }
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            tokens.append(data["token"])
        
        # Verify all tokens are unique
        assert len(tokens) == len(set(tokens)), "Tokens are not unique"
        
        # Cleanup all tokens
        for token in tokens:
            session.post(
                f"{base_url}/api/token/disable",
                data={"api_key": test_config.API_KEY, "token": token}
            )


@pytest.mark.token_mgmt
@pytest.mark.error
class TestTokenCreationErrors:
    """Test error scenarios for token creation"""
    
    def test_create_token_invalid_api_key(self, base_url, session, test_config):
        """Token creation with invalid API key should return 401"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": "invalid_key_12345678901234567890",
                "duration": test_config.TEST_TOKEN_DURATION,
                "bandwidth_down": 100,
                "bandwidth_up": 50
            }
        )
        
        assert response.status_code == 401
        data = response.json()
        assert data["success"] is False
        assert "Invalid API key" in data["error"]
    
    def test_create_token_missing_api_key(self, base_url, session, test_config):
        """Token creation without API key should return 400"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "duration": test_config.TEST_TOKEN_DURATION,
                "bandwidth_down": 100,
                "bandwidth_up": 50
            }
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
    
    def test_create_token_missing_duration(self, base_url, session, test_config):
        """Token creation without duration should return 400"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "bandwidth_down": 100,
                "bandwidth_up": 50
            }
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
    
    def test_create_token_duration_too_short(self, base_url, session, test_config):
        """Token creation with duration below minimum should return 400"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.MIN_TOKEN_DURATION - 1,  # 29 minutes
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
    
    def test_create_token_duration_too_long(self, base_url, session, test_config):
        """Token creation with duration above maximum should return 400"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.MAX_TOKEN_DURATION + 1,  # Over 30 days
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False


@pytest.mark.token_mgmt
class TestTokenInfo:
    """Tests for GET /api/token/info endpoint"""
    
    def test_query_token_info_basic(self, base_url, session, test_config, test_token):
        """Query information for an existing token"""
        response = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": test_token
            }
        )
        
        assert response.status_code == 200
        assert_response_time(response)
        
        data = response.json()
        
        # Verify response structure
        assert data["success"] is True
        assert data["token"] == test_token
        assert data["status"] in ["unused", "active", "expired"]
        
        # Verify all required fields
        required_fields = [
            "token", "status", "created", "first_use", "duration_minutes",
            "expires_at", "remaining_seconds", "bandwidth_down_mb", "bandwidth_up_mb",
            "bandwidth_used_down_mb", "bandwidth_used_up_mb", "usage_count",
            "device_count", "max_devices"
        ]
        
        for field in required_fields:
            assert field in data, f"Missing field: {field}"
    
    def test_query_token_info_field_types(self, base_url, session, test_config, test_token):
        """Verify field types in token info response"""
        response = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": test_token
            }
        )
        
        data = response.json()
        
        # Type assertions
        assert isinstance(data["token"], str)
        assert isinstance(data["status"], str)
        assert isinstance(data["created"], int)
        assert isinstance(data["first_use"], int)
        assert isinstance(data["duration_minutes"], int)
        assert isinstance(data["expires_at"], int)
        assert isinstance(data["remaining_seconds"], int)
        assert isinstance(data["bandwidth_down_mb"], int)
        assert isinstance(data["bandwidth_up_mb"], int)
        assert isinstance(data["bandwidth_used_down_mb"], int)
        assert isinstance(data["bandwidth_used_up_mb"], int)
        assert isinstance(data["usage_count"], int)
        assert isinstance(data["device_count"], int)
        assert isinstance(data["max_devices"], int)
    
    def test_query_token_info_unused_token(self, base_url, session, test_config, test_token):
        """Verify unused token has expected values"""
        response = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": test_token
            }
        )
        
        data = response.json()
        
        # Unused token should have specific characteristics
        assert data["status"] == "unused"
        assert data["first_use"] == 0
        assert data["usage_count"] == 0
        assert data["device_count"] == 0
        assert data["bandwidth_used_down_mb"] == 0
        assert data["bandwidth_used_up_mb"] == 0
        assert data["remaining_seconds"] == 0
        assert_valid_timestamp(data["created"])
    
    def test_query_token_info_parameters(self, base_url, session, test_config, test_token):
        """Verify token parameters match creation"""
        response = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": test_token
            }
        )
        
        data = response.json()
        
        # Should match creation parameters
        assert data["duration_minutes"] == test_config.TEST_TOKEN_DURATION
        assert data["bandwidth_down_mb"] == test_config.TEST_BANDWIDTH_DOWN
        assert data["bandwidth_up_mb"] == test_config.TEST_BANDWIDTH_UP
        assert data["max_devices"] == test_config.MAX_DEVICES_PER_TOKEN


@pytest.mark.token_mgmt
@pytest.mark.error
class TestTokenInfoErrors:
    """Test error scenarios for token info endpoint"""
    
    def test_query_nonexistent_token(self, base_url, session, test_config):
        """Query non-existent token should return 404"""
        response = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": "FAKE1234"
            }
        )
        
        assert response.status_code == 404
        data = response.json()
        assert data["success"] is False
        assert data["error_code"] == "TOKEN_NOT_FOUND"
    
    def test_query_token_invalid_api_key(self, base_url, session, test_config, test_token):
        """Query with invalid API key should return 401"""
        response = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": "invalid_key_12345678901234567890",
                "token": test_token
            }
        )
        
        assert response.status_code == 401
        data = response.json()
        assert data["success"] is False
        assert "Invalid API key" in data["error"]
    
    def test_query_token_missing_parameters(self, base_url, session, test_config):
        """Query without required parameters should return 400"""
        # Missing token
        response = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY
            }
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
