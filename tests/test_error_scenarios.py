"""
Error Scenarios Integration Tests

Tests for all error conditions and edge cases across all endpoints.
Validates HTTP status codes: 400, 401, 403, 404
"""

import pytest


@pytest.mark.error
class TestAuthenticationErrors:
    """Test 401 Unauthorized errors across all endpoints"""
    
    def test_invalid_api_key_token_create(self, base_url, session, test_config):
        """POST /api/token with invalid API key returns 401"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": "invalid_key_abcdefghijklmnopqrst",
                "duration": test_config.TEST_TOKEN_DURATION,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        assert response.status_code == 401
        data = response.json()
        assert data["success"] is False
        assert "Invalid API key" in data["error"]
    
    def test_invalid_api_key_token_info(self, base_url, session, test_config, test_token):
        """GET /api/token/info with invalid API key returns 401"""
        response = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": "invalid_key_abcdefghijklmnopqrst",
                "token": test_token
            }
        )
        
        assert response.status_code == 401
        data = response.json()
        assert data["success"] is False
        assert "Invalid API key" in data["error"]
    
    def test_invalid_api_key_token_disable(self, base_url, session, test_config, test_token):
        """POST /api/token/disable with invalid API key returns 401"""
        response = session.post(
            f"{base_url}/api/token/disable",
            data={
                "api_key": "invalid_key_abcdefghijklmnopqrst",
                "token": test_token
            }
        )
        
        assert response.status_code == 401
        data = response.json()
        assert data["success"] is False
        assert "Invalid API key" in data["error"]
    
    def test_invalid_api_key_token_extend(self, base_url, session, test_config, test_token):
        """POST /api/token/extend with invalid API key returns 401"""
        response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": "invalid_key_abcdefghijklmnopqrst",
                "token": test_token,
                "additional_minutes": 60
            }
        )
        
        assert response.status_code == 401
        data = response.json()
        assert data["success"] is False
        assert "Invalid API key" in data["error"]
    
    def test_missing_api_key_token_create(self, base_url, session, test_config):
        """POST /api/token without API key returns 400"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "duration": test_config.TEST_TOKEN_DURATION,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
    
    def test_empty_api_key_token_create(self, base_url, session, test_config):
        """POST /api/token with empty API key returns 400 or 401"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": "",
                "duration": test_config.TEST_TOKEN_DURATION,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        assert response.status_code in [400, 401]
        data = response.json()
        assert data["success"] is False


@pytest.mark.error
@pytest.mark.skip(reason="Requires execution from AP network 192.168.4.x")
class TestAuthorizationErrors:
    """Test 403 Forbidden errors (API uplink-only enforcement)"""
    
    def test_403_token_create_from_ap(self, base_url, session, test_config):
        """POST /api/token from AP network returns 403"""
        # This test must be run from a device connected to 192.168.4.x
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.TEST_TOKEN_DURATION,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        assert response.status_code == 403
        data = response.json()
        assert data["success"] is False
        assert "uplink" in data["error"].lower()
    
    def test_403_token_info_from_ap(self, base_url, session, test_config):
        """GET /api/token/info from AP network returns 403"""
        response = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": "TEST1234"
            }
        )
        
        assert response.status_code == 403
    
    def test_403_token_disable_from_ap(self, base_url, session, test_config):
        """POST /api/token/disable from AP network returns 403"""
        response = session.post(
            f"{base_url}/api/token/disable",
            data={
                "api_key": test_config.API_KEY,
                "token": "TEST1234"
            }
        )
        
        assert response.status_code == 403
    
    def test_403_token_extend_from_ap(self, base_url, session, test_config):
        """POST /api/token/extend from AP network returns 403"""
        response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": test_config.API_KEY,
                "token": "TEST1234",
                "additional_minutes": 60
            }
        )
        
        assert response.status_code == 403


@pytest.mark.error
class TestNotFoundErrors:
    """Test 404 Not Found errors"""
    
    def test_404_token_info_nonexistent(self, base_url, session, test_config):
        """GET /api/token/info for non-existent token returns 404"""
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
    
    def test_404_token_disable_nonexistent(self, base_url, session, test_config):
        """POST /api/token/disable for non-existent token returns 404"""
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
    
    def test_404_token_extend_nonexistent(self, base_url, session, test_config):
        """POST /api/token/extend for non-existent token returns 404"""
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
    
    def test_404_after_token_disabled(self, base_url, session, test_config):
        """Querying disabled token returns 404"""
        # Create and immediately disable
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
        
        session.post(
            f"{base_url}/api/token/disable",
            data={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        
        # Query should return 404
        response = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        
        assert response.status_code == 404
    
    def test_404_invalid_endpoint(self, base_url, session):
        """Request to non-existent endpoint returns 404"""
        response = session.get(f"{base_url}/api/nonexistent")
        
        assert response.status_code == 404


@pytest.mark.error
class TestBadRequestErrors:
    """Test 400 Bad Request errors"""
    
    def test_400_token_create_missing_duration(self, base_url, session, test_config):
        """POST /api/token without duration returns 400"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
    
    def test_400_token_create_duration_too_short(self, base_url, session, test_config):
        """POST /api/token with duration < 30 minutes returns 400"""
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
    
    def test_400_token_create_duration_too_long(self, base_url, session, test_config):
        """POST /api/token with duration > 30 days returns 400"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.MAX_TOKEN_DURATION + 1,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
    
    def test_400_token_create_invalid_duration_format(self, base_url, session, test_config):
        """POST /api/token with non-numeric duration returns 400"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": "invalid",
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
    
    def test_400_token_create_negative_duration(self, base_url, session, test_config):
        """POST /api/token with negative duration returns 400"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": -30,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
    
    def test_400_token_create_negative_bandwidth(self, base_url, session, test_config):
        """POST /api/token with negative bandwidth returns 400"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.TEST_TOKEN_DURATION,
                "bandwidth_down": -100,
                "bandwidth_up": -50
            }
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
    
    def test_400_token_info_missing_token(self, base_url, session, test_config):
        """GET /api/token/info without token parameter returns 400"""
        response = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY
            }
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
    
    def test_400_token_disable_missing_token(self, base_url, session, test_config):
        """POST /api/token/disable without token returns 400"""
        response = session.post(
            f"{base_url}/api/token/disable",
            data={
                "api_key": test_config.API_KEY
            }
        )
        
        assert response.status_code == 400
        data = response.json()
        assert data["success"] is False
    
    def test_400_token_extend_missing_additional_minutes(self, base_url, session, test_config, test_token):
        """POST /api/token/extend - reset operation always succeeds with valid token"""
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
    
    def test_400_token_extend_below_minimum(self, base_url, session, test_config, test_token):
        """POST /api/token/extend - reset operation ignores additional parameters"""
        response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": test_config.API_KEY,
                "token": test_token,
                "additional_minutes": test_config.MIN_TOKEN_EXTENSION - 1
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
    
    def test_400_token_extend_above_maximum(self, base_url, session, test_config, test_token):
        """POST /api/token/extend - reset operation ignores additional parameters"""
        response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": test_config.API_KEY,
                "token": test_token,
                "additional_minutes": test_config.MAX_TOKEN_EXTENSION + 1
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
    
    def test_400_token_extend_negative_amount(self, base_url, session, test_config, test_token):
        """POST /api/token/extend - reset operation ignores additional parameters"""
        response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": test_config.API_KEY,
                "token": test_token,
                "additional_minutes": -60
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True


@pytest.mark.error
@pytest.mark.integration
class TestErrorResponseStructure:
    """Verify error responses have consistent structure"""
    
    def test_error_response_has_success_false(self, base_url, session, test_config):
        """All error responses should have success=false"""
        # 401 error
        response_401 = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": "invalid_key_abc",
                "duration": 60,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        assert response_401.json()["success"] is False
        
        # 404 error
        response_404 = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": "FAKE1234"
            }
        )
        
        assert response_404.json()["success"] is False
        
        # 400 error
        response_400 = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": -30,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        assert response_400.json()["success"] is False
    
    def test_error_response_has_error_field(self, base_url, session, test_config):
        """Error responses should have descriptive error field"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": "invalid_key_abc",
                "duration": 60,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        data = response.json()
        assert "error" in data
        assert isinstance(data["error"], str)
        assert len(data["error"]) > 0
    
    def test_404_error_has_error_code(self, base_url, session, test_config):
        """404 errors should include error_code field"""
        response = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": "FAKE1234"
            }
        )
        
        data = response.json()
        assert "error_code" in data
        assert data["error_code"] == "TOKEN_NOT_FOUND"
    
    def test_error_response_json_format(self, base_url, session, test_config):
        """Error responses should be valid JSON"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": "invalid_key_abc",
                "duration": 60,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        # Should not raise exception
        data = response.json()
        assert isinstance(data, dict)


@pytest.mark.error
@pytest.mark.edge_case
class TestEdgeCases:
    """Test edge cases and boundary conditions"""
    
    def test_token_with_exact_minimum_duration(self, base_url, session, test_config):
        """Token with exactly 30 minutes should succeed"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.MIN_TOKEN_DURATION,  # Exactly 30
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        assert response.status_code == 200
        
        # Cleanup
        token = response.json()["token"]
        session.post(
            f"{base_url}/api/token/disable",
            data={"api_key": test_config.API_KEY, "token": token}
        )
    
    def test_token_with_exact_maximum_duration(self, base_url, session, test_config):
        """Token with exactly 30 days should succeed"""
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.MAX_TOKEN_DURATION,  # Exactly 43200
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        
        assert response.status_code == 200
        
        # Cleanup
        token = response.json()["token"]
        session.post(
            f"{base_url}/api/token/disable",
            data={"api_key": test_config.API_KEY, "token": token}
        )
    
    def test_extend_with_exact_minimum(self, base_url, session, test_config, test_token):
        """Extend with exactly 30 minutes should succeed"""
        response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": test_config.API_KEY,
                "token": test_token,
                "additional_minutes": test_config.MIN_TOKEN_EXTENSION
            }
        )
        
        assert response.status_code == 200
    
    def test_extend_with_exact_maximum(self, base_url, session, test_config, test_token):
        """Extend with exactly 7 days should succeed"""
        response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": test_config.API_KEY,
                "token": test_token,
                "additional_minutes": test_config.MAX_TOKEN_EXTENSION
            }
        )
        
        assert response.status_code == 200
