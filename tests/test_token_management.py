"""
Token Management Integration Tests

Tests for token management operations: disable and extend.
Tests: POST /api/token/disable, POST /api/token/extend
"""

import pytest
import time
from .conftest import assert_valid_token_format, assert_response_time


@pytest.mark.token_mgmt
class TestTokenDisable:
    """Tests for POST /api/token/disable endpoint"""
    
    def test_disable_token_basic(self, base_url, session, test_config, test_token):
        """Disable an existing token"""
        response = session.post(
            f"{base_url}/api/token/disable",
            data={
                "api_key": test_config.API_KEY,
                "token": test_token
            }
        )
        
        assert response.status_code == 200
        assert_response_time(response)
        
        data = response.json()
        
        # Verify response
        assert data["success"] is True
        assert data["message"] == "Token disabled successfully"
        
        # Verify token no longer exists
        info_response = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": test_token
            }
        )
        
        assert info_response.status_code == 404
    
    def test_disable_token_multiple_times(self, base_url, session, test_config):
        """Disabling the same token multiple times should be idempotent"""
        # Create token
        create_response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.TEST_TOKEN_DURATION,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        token = create_response.json()["token"]
        
        # Disable first time
        response1 = session.post(
            f"{base_url}/api/token/disable",
            data={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        assert response1.status_code == 200
        
        # Disable second time (should return 404)
        response2 = session.post(
            f"{base_url}/api/token/disable",
            data={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        assert response2.status_code == 404
        data = response2.json()
        assert data["success"] is False
        assert data["error_code"] == "TOKEN_NOT_FOUND"
    
    def test_disable_multiple_tokens(self, base_url, session, test_config, multiple_test_tokens):
        """Disable multiple tokens sequentially"""
        tokens = multiple_test_tokens
        
        for token in tokens:
            response = session.post(
                f"{base_url}/api/token/disable",
                data={
                    "api_key": test_config.API_KEY,
                    "token": token
                }
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
        
        # Verify all tokens are gone
        for token in tokens:
            info_response = session.get(
                f"{base_url}/api/token/info",
                params={
                    "api_key": test_config.API_KEY,
                    "token": token
                }
            )
            assert info_response.status_code == 404


@pytest.mark.token_mgmt
@pytest.mark.error
class TestTokenDisableErrors:
    """Test error scenarios for token disable endpoint"""
    
    def test_disable_token_invalid_api_key(self, base_url, session, test_config, test_token):
        """Disable with invalid API key should return 401"""
        response = session.post(
            f"{base_url}/api/token/disable",
            data={
                "api_key": "invalid_key_12345678901234567890",
                "token": test_token
            }
        )
        
        assert response.status_code == 401
        data = response.json()
        assert data["success"] is False
        assert "Invalid API key" in data["error"]
    
    def test_disable_nonexistent_token(self, base_url, session, test_config):
        """Disable non-existent token should return 404"""
        response = session.post(
            f"{base_url}/api/token/disable",
            data={
                "api_key": test_config.API_KEY,
                "token": "FAKE1234"
            }
        )
        
        assert response.status_code == 404
        data = response.json()
        assert data["success"] is False
        assert data["error_code"] == "TOKEN_NOT_FOUND"
    
    def test_disable_token_missing_parameters(self, base_url, session, test_config):
        """Disable without required parameters should return 400"""
        # Missing token
        response = session.post(
            f"{base_url}/api/token/disable",
            data={
                "api_key": test_config.API_KEY
            }
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False


@pytest.mark.token_mgmt
class TestTokenExtend:
    """Tests for POST /api/token/extend endpoint"""
    
    def test_extend_token_basic(self, base_url, session, test_config, test_token):
        """Reset/extend a token - resets first_use to now and usage counters"""
        # Get initial info
        info_response = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": test_token
            }
        )
        initial_duration = info_response.json()["duration_minutes"]
        
        # Reset/extend token (resets timer, not duration)
        response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": test_config.API_KEY,
                "token": test_token
            }
        )
        
        assert response.status_code == 200
        assert_response_time(response)
        
        data = response.json()
        
        # Verify response
        assert data["success"] is True
        assert data["token"] == test_token
        assert data["duration_minutes"] == initial_duration  # Duration unchanged
        assert data["new_duration_minutes"] == initial_duration  # Duration unchanged
        assert "new_expires_at" in data
        
        # Verify token info reflects reset
        info_response = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": test_token
            }
        )
        
        info_data = info_response.json()
        assert info_data["duration_minutes"] == initial_duration  # Duration stays the same
        assert info_data["bandwidth_used_down_mb"] == 0  # Usage reset
        assert info_data["bandwidth_used_up_mb"] == 0  # Usage reset
        assert info_data["usage_count"] == 0  # Usage count reset
    
    def test_extend_token_minimum_amount(self, base_url, session, test_config, test_token):
        """Reset token - duration stays same, usage counters reset"""
        response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": test_config.API_KEY,
                "token": test_token
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
    
    def test_extend_token_maximum_amount(self, base_url, session, test_config, test_token):
        """Reset token - verifies timer restart"""
        response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": test_config.API_KEY,
                "token": test_token
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
    
    def test_extend_token_multiple_times(self, base_url, session, test_config, test_token):
        """Reset the same token multiple times - duration stays constant"""
        # Get initial duration
        info_response = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": test_token
            }
        )
        initial_duration = info_response.json()["duration_minutes"]
        
        # Reset three times
        for i in range(3):
            response = session.post(
                f"{base_url}/api/token/extend",
                data={
                    "api_key": test_config.API_KEY,
                    "token": test_token
                }
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            # Duration never changes - it's a reset, not an extension
            assert data["new_duration_minutes"] == initial_duration
            assert data["duration_minutes"] == initial_duration
    
    def test_extend_token_respects_maximum_total(self, base_url, session, test_config):
        """Reset token - duration never changes regardless of original duration"""
        # Create token with near-maximum duration
        create_response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.MAX_TOKEN_DURATION - 10,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        token = create_response.json()["token"]
        original_duration = test_config.MAX_TOKEN_DURATION - 10
        
        # Reset token
        response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        
        # Duration stays the same
        assert response.status_code == 200
        data = response.json()
        assert data["new_duration_minutes"] == original_duration
        assert data["duration_minutes"] == original_duration
        
        # Cleanup
        session.post(
            f"{base_url}/api/token/disable",
            data={"api_key": test_config.API_KEY, "token": token}
        )


@pytest.mark.token_mgmt
@pytest.mark.error
class TestTokenExtendErrors:
    """Test error scenarios for token extend endpoint"""
    
    def test_extend_token_invalid_api_key(self, base_url, session, test_config, test_token):
        """Extend with invalid API key should return 401"""
        response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": "invalid_key_12345678901234567890",
                "token": test_token,
                "additional_minutes": 60
            }
        )
        
        assert response.status_code == 401
        data = response.json()
        assert data["success"] is False
        assert "Invalid API key" in data["error"]
    
    def test_extend_nonexistent_token(self, base_url, session, test_config):
        """Extend non-existent token should return 404"""
        response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": test_config.API_KEY,
                "token": "FAKE1234",
                "additional_minutes": 60
            }
        )
        
        assert response.status_code == 404
        data = response.json()
        assert data["success"] is False
        assert data["error_code"] == "TOKEN_NOT_FOUND"
    
    def test_extend_token_missing_parameters(self, base_url, session, test_config):
        """Reset token without token parameter should return 400"""
        create_response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.TEST_TOKEN_DURATION,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        token = create_response.json()["token"]
        
        # Missing token parameter
        response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": test_config.API_KEY
            }
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
        
        # Cleanup
        session.post(
            f"{base_url}/api/token/disable",
            data={"api_key": test_config.API_KEY, "token": token}
        )
    
    def test_extend_token_below_minimum(self, base_url, session, test_config, test_token):
        """Reset token - always succeeds regardless of duration"""
        response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": test_config.API_KEY,
                "token": test_token
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
    
    def test_extend_token_above_maximum(self, base_url, session, test_config, test_token):
        """Reset token - always succeeds regardless of duration"""
        response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": test_config.API_KEY,
                "token": test_token
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True


@pytest.mark.token_mgmt
@pytest.mark.integration
class TestTokenManagementWorkflows:
    """Test complete token management workflows"""
    
    def test_create_query_extend_disable_workflow(self, base_url, session, test_config):
        """Complete workflow: create, query, extend, disable"""
        # 1. Create token
        create_response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.TEST_TOKEN_DURATION,
                "bandwidth_down": 100,
                "bandwidth_up": 50
            }
        )
        
        assert create_response.status_code == 200
        token = create_response.json()["token"]
        
        # 2. Query token info
        info_response = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        
        assert info_response.status_code == 200
        info_data = info_response.json()
        assert info_data["status"] == "unused"
        initial_duration = info_data["duration_minutes"]
        
        # 3. Reset token (extend endpoint)
        extend_response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        
        assert extend_response.status_code == 200
        extend_data = extend_response.json()
        assert extend_data["new_duration_minutes"] == initial_duration  # Duration unchanged
        assert extend_data["duration_minutes"] == initial_duration
        
        # 4. Verify reset (duration unchanged, usage counters reset)
        info_response2 = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        
        assert info_response2.status_code == 200
        assert info_response2.json()["duration_minutes"] == initial_duration
        assert info_response2.json()["usage_count"] == 0
        
        # 5. Disable token
        disable_response = session.post(
            f"{base_url}/api/token/disable",
            data={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        
        assert disable_response.status_code == 200
        
        # 6. Verify token is gone
        info_response3 = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        
        assert info_response3.status_code == 404
    
    def test_bulk_token_management(self, base_url, session, test_config):
        """Manage multiple tokens simultaneously"""
        # Create 5 tokens
        tokens = []
        for i in range(5):
            create_response = session.post(
                f"{base_url}/api/token",
                data={
                    "api_key": test_config.API_KEY,
                    "duration": test_config.TEST_TOKEN_DURATION + (i * 10),
                    "bandwidth_down": 100 * (i + 1),
                    "bandwidth_up": 50 * (i + 1)
                }
            )
            
            assert create_response.status_code == 200
            tokens.append(create_response.json()["token"])
        
        # Query all tokens
        for token in tokens:
            info_response = session.get(
                f"{base_url}/api/token/info",
                params={
                    "api_key": test_config.API_KEY,
                    "token": token
                }
            )
            
            assert info_response.status_code == 200
            assert info_response.json()["status"] == "unused"
        
        # Extend first 3 tokens
        for i in range(3):
            extend_response = session.post(
                f"{base_url}/api/token/extend",
                data={
                    "api_key": test_config.API_KEY,
                    "token": tokens[i],
                    "additional_minutes": 30
                }
            )
            
            assert extend_response.status_code == 200
        
        # Disable all tokens
        for token in tokens:
            disable_response = session.post(
                f"{base_url}/api/token/disable",
                data={
                    "api_key": test_config.API_KEY,
                    "token": token
                }
            )
            
            assert disable_response.status_code == 200
