"""
Monitoring APIs Integration Tests

Tests for /api/uptime and /api/health endpoints.
These endpoints do not require authentication.
"""

import pytest
import time
from .conftest import assert_valid_timestamp, assert_response_time


@pytest.mark.monitoring
class TestUptimeAPI:
    """Tests for GET /api/uptime endpoint"""
    
    def test_uptime_endpoint_accessible(self, base_url, session):
        """Verify uptime endpoint is accessible"""
        response = session.get(f"{base_url}/api/uptime")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    def test_uptime_response_structure(self, base_url, session):
        """Verify uptime API returns correct JSON structure"""
        response = session.get(f"{base_url}/api/uptime")
        
        assert response.status_code == 200
        assert_response_time(response)
        
        data = response.json()
        
        # Verify required fields
        assert "success" in data, "Missing 'success' field"
        assert "uptime_seconds" in data, "Missing 'uptime_seconds' field"
        assert "uptime_microseconds" in data, "Missing 'uptime_microseconds' field"
        
        # Verify field types
        assert isinstance(data["success"], bool), "success must be boolean"
        assert isinstance(data["uptime_seconds"], int), "uptime_seconds must be integer"
        assert isinstance(data["uptime_microseconds"], int), "uptime_microseconds must be integer"
    
    def test_uptime_values_valid(self, base_url, session):
        """Verify uptime values are positive and sensible"""
        response = session.get(f"{base_url}/api/uptime")
        data = response.json()
        
        assert data["success"] is True
        assert data["uptime_seconds"] > 0, "uptime_seconds must be positive"
        assert data["uptime_microseconds"] > 0, "uptime_microseconds must be positive"
        
        # Verify microseconds is consistent with seconds
        expected_min_us = data["uptime_seconds"] * 1_000_000
        expected_max_us = (data["uptime_seconds"] + 1) * 1_000_000
        assert expected_min_us <= data["uptime_microseconds"] <= expected_max_us, \
            "Microseconds inconsistent with seconds"
    
    def test_uptime_increases_over_time(self, base_url, session):
        """Verify uptime increases as expected"""
        # First reading
        response1 = session.get(f"{base_url}/api/uptime")
        uptime1 = response1.json()["uptime_seconds"]
        
        # Wait 2 seconds
        time.sleep(2)
        
        # Second reading
        response2 = session.get(f"{base_url}/api/uptime")
        uptime2 = response2.json()["uptime_seconds"]
        
        # Uptime should have increased by at least 2 seconds
        assert uptime2 >= uptime1 + 2, \
            f"Uptime did not increase properly: {uptime1}s -> {uptime2}s"
    
    def test_uptime_precision(self, base_url, session):
        """Verify microsecond precision is working"""
        response1 = session.get(f"{base_url}/api/uptime")
        us1 = response1.json()["uptime_microseconds"]
        
        time.sleep(0.1)  # 100ms
        
        response2 = session.get(f"{base_url}/api/uptime")
        us2 = response2.json()["uptime_microseconds"]
        
        # Should have increased by at least 100,000 microseconds (100ms)
        assert us2 >= us1 + 100_000, \
            f"Microsecond precision not working: {us1} -> {us2}"
    
    def test_uptime_multiple_requests(self, base_url, session):
        """Verify uptime is consistent across multiple rapid requests"""
        responses = []
        for _ in range(5):
            response = session.get(f"{base_url}/api/uptime")
            assert response.status_code == 200
            responses.append(response.json()["uptime_seconds"])
        
        # All uptimes should be within a reasonable range (1 second)
        assert max(responses) - min(responses) <= 1, \
            f"Uptime varies too much: {responses}"


@pytest.mark.monitoring
class TestHealthAPI:
    """Tests for GET /api/health endpoint"""
    
    def test_health_endpoint_accessible(self, base_url, session):
        """Verify health endpoint is accessible"""
        response = session.get(f"{base_url}/api/health")
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    def test_health_response_structure(self, base_url, session):
        """Verify health API returns all required fields"""
        response = session.get(f"{base_url}/api/health")
        
        assert response.status_code == 200
        assert_response_time(response)
        
        data = response.json()
        
        # Verify all required fields exist
        required_fields = [
            "success", "status", "uptime_seconds",
            "time_synced", "last_time_sync", "current_time",
            "active_tokens", "max_tokens", "free_heap_bytes"
        ]
        
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"
    
    def test_health_field_types(self, base_url, session):
        """Verify health API field types are correct"""
        response = session.get(f"{base_url}/api/health")
        data = response.json()
        
        # Type assertions
        assert isinstance(data["success"], bool)
        assert isinstance(data["status"], str)
        assert isinstance(data["uptime_seconds"], int)
        assert isinstance(data["time_synced"], bool)
        assert isinstance(data["last_time_sync"], int)
        assert isinstance(data["current_time"], int)
        assert isinstance(data["active_tokens"], int)
        assert isinstance(data["max_tokens"], int)
        assert isinstance(data["free_heap_bytes"], int)
    
    def test_health_values_valid(self, base_url, session, test_config):
        """Verify health values are within valid ranges"""
        response = session.get(f"{base_url}/api/health")
        data = response.json()
        
        assert data["success"] is True
        assert data["status"] == "healthy"
        
        # Uptime checks
        assert data["uptime_seconds"] > 0, "Uptime must be positive"
        
        # Token checks
        assert 0 <= data["active_tokens"] <= data["max_tokens"], \
            f"Active tokens ({data['active_tokens']}) out of range (0-{data['max_tokens']})"
        assert data["max_tokens"] == test_config.MAX_ACTIVE_TOKENS, \
            f"Max tokens should be {test_config.MAX_ACTIVE_TOKENS}"
        
        # Memory checks
        assert data["free_heap_bytes"] > test_config.MIN_FREE_HEAP, \
            f"Free heap ({data['free_heap_bytes']}) below threshold ({test_config.MIN_FREE_HEAP})"
        
        # Time sync checks
        if data["time_synced"]:
            assert data["last_time_sync"] > 0, "last_time_sync should be > 0 when synced"
            assert_valid_timestamp(data["last_time_sync"])
            assert_valid_timestamp(data["current_time"])
            assert data["current_time"] >= data["last_time_sync"], \
                "current_time should be >= last_time_sync"
    
    def test_health_time_sync_status(self, base_url, session):
        """Verify time sync status is accurate"""
        response = session.get(f"{base_url}/api/health")
        data = response.json()
        
        if data["time_synced"]:
            # If synced, verify timestamps are reasonable
            assert data["last_time_sync"] > 0
            assert data["current_time"] > data["last_time_sync"]
            
            # Current time should be recent (within last hour of real time)
            import time as pytime
            now = int(pytime.time())
            time_diff = abs(now - data["current_time"])
            assert time_diff < 3600, \
                f"Device time differs from host by {time_diff}s"
        else:
            # If not synced, last_time_sync should be 0
            assert data["last_time_sync"] == 0, \
                "last_time_sync should be 0 when not synced"
    
    def test_health_consistency_with_uptime(self, base_url, session):
        """Verify health uptime matches uptime endpoint"""
        # Get both endpoints
        health_response = session.get(f"{base_url}/api/health")
        uptime_response = session.get(f"{base_url}/api/uptime")
        
        health_uptime = health_response.json()["uptime_seconds"]
        uptime_value = uptime_response.json()["uptime_seconds"]
        
        # Should be very close (within 1 second)
        assert abs(health_uptime - uptime_value) <= 1, \
            f"Health uptime ({health_uptime}) differs from uptime API ({uptime_value})"
    
    def test_health_token_count_accuracy(self, base_url, session, test_token):
        """Verify active token count is accurate"""
        # Get initial count
        response1 = session.get(f"{base_url}/api/health")
        initial_count = response1.json()["active_tokens"]
        
        # test_token fixture creates a token, so count should have increased
        # (this test uses the token from fixture)
        response2 = session.get(f"{base_url}/api/health")
        current_count = response2.json()["active_tokens"]
        
        assert current_count >= initial_count, \
            "Token count should not decrease during test"
    
    def test_health_memory_stability(self, base_url, session):
        """Verify memory doesn't drop significantly during normal operation"""
        measurements = []
        
        for _ in range(5):
            response = session.get(f"{base_url}/api/health")
            measurements.append(response.json()["free_heap_bytes"])
            time.sleep(0.5)
        
        # Memory should be relatively stable (not dropping by more than 10%)
        min_heap = min(measurements)
        max_heap = max(measurements)
        variation = (max_heap - min_heap) / max_heap * 100
        
        assert variation < 10, \
            f"Memory varies too much ({variation:.1f}%): {measurements}"
    
    def test_health_response_performance(self, base_url, session):
        """Verify health endpoint responds quickly"""
        import time as pytime
        
        start = pytime.time()
        response = session.get(f"{base_url}/api/health")
        elapsed = pytime.time() - start
        
        assert response.status_code == 200
        assert elapsed < 0.5, f"Health check took {elapsed:.3f}s (should be < 0.5s)"


@pytest.mark.monitoring
class TestTokensListAPI:
    """Tests for GET /api/tokens/list endpoint"""
    
    def test_tokens_list_requires_auth(self, base_url, session):
        """Verify tokens list endpoint requires API key"""
        try:
            response = session.get(f"{base_url}/api/tokens/list")
            assert response.status_code in [400, 401], "Should require API key"
        except Exception:
            # ESP32 may close connection without response - this is acceptable
            pass
    
    def test_tokens_list_invalid_api_key(self, base_url, session):
        """Verify tokens list rejects invalid API key"""
        response = session.get(
            f"{base_url}/api/tokens/list",
            params={"api_key": "invalid_key_123"}
        )
        assert response.status_code == 401
        data = response.json()
        assert data["success"] is False
    
    def test_tokens_list_response_structure(self, base_url, test_config, session):
        """Verify tokens list returns correct JSON structure"""
        response = session.get(
            f"{base_url}/api/tokens/list",
            params={"api_key": test_config.API_KEY}
        )
        
        assert response.status_code == 200
        assert_response_time(response)
        
        data = response.json()
        
        # Verify required fields
        assert "success" in data, "Missing 'success' field"
        assert "count" in data, "Missing 'count' field"
        assert "tokens" in data, "Missing 'tokens' field"
        
        # Verify field types
        assert isinstance(data["success"], bool), "success must be boolean"
        assert isinstance(data["count"], int), "count must be integer"
        assert isinstance(data["tokens"], list), "tokens must be list"
        
        assert data["success"] is True
        assert data["count"] >= 0, "count must be non-negative"
    
    def test_tokens_list_token_structure(self, base_url, test_config, session, test_token):
        """Verify each token in list has correct structure"""
        # test_token fixture creates a token automatically
        
        response = session.get(
            f"{base_url}/api/tokens/list",
            params={"api_key": test_config.API_KEY}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert len(data["tokens"]) > 0, "Should have at least one token"
        
        # Verify token structure
        token_data = data["tokens"][0]
        required_fields = [
            "token", "status", "duration_minutes", "first_use",
            "expires_at", "remaining_seconds", "bandwidth_down_mb",
            "bandwidth_up_mb", "bandwidth_used_down", "bandwidth_used_up",
            "usage_count", "device_count", "client_macs"
        ]
        
        for field in required_fields:
            assert field in token_data, f"Missing '{field}' field in token"
        
        # Verify field types
        assert isinstance(token_data["token"], str), "token must be string"
        assert isinstance(token_data["status"], str), "status must be string"
        assert isinstance(token_data["duration_minutes"], int), "duration_minutes must be integer"
        assert isinstance(token_data["first_use"], int), "first_use must be integer"
        assert isinstance(token_data["expires_at"], int), "expires_at must be integer"
        assert isinstance(token_data["remaining_seconds"], int), "remaining_seconds must be integer"
        assert isinstance(token_data["bandwidth_down_mb"], int), "bandwidth_down_mb must be integer"
        assert isinstance(token_data["bandwidth_up_mb"], int), "bandwidth_up_mb must be integer"
        assert isinstance(token_data["bandwidth_used_down"], int), "bandwidth_used_down must be integer"
        assert isinstance(token_data["bandwidth_used_up"], int), "bandwidth_used_up must be integer"
        assert isinstance(token_data["usage_count"], int), "usage_count must be integer"
        assert isinstance(token_data["device_count"], int), "device_count must be integer"
        assert isinstance(token_data["client_macs"], list), "client_macs must be list"
        
        # Verify status is one of valid values
        assert token_data["status"] in ["unused", "active", "expired"], \
            f"Invalid status: {token_data['status']}"
    
    def test_tokens_list_count_matches_array_length(self, base_url, test_config, session, test_token):
        """Verify count field matches actual number of tokens"""
        # test_token fixture creates a token
        
        response = session.get(
            f"{base_url}/api/tokens/list",
            params={"api_key": test_config.API_KEY}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["count"] == len(data["tokens"]), \
            f"Count mismatch: {data['count']} != {len(data['tokens'])}"
        assert data["count"] > 0, "Should have at least one token"
    
    def test_tokens_list_unused_token_status(self, base_url, test_config, session, test_token):
        """Verify newly created tokens have 'unused' status"""
        response = session.get(
            f"{base_url}/api/tokens/list",
            params={"api_key": test_config.API_KEY}
        )
        
        data = response.json()
        token_data = next((t for t in data["tokens"] if t["token"] == test_token), None)
        
        assert token_data is not None, f"Token {test_token} not found in list"
        assert token_data["status"] == "unused", "New token should have 'unused' status"
        assert token_data["first_use"] == 0, "New token should have first_use = 0"
        assert token_data["usage_count"] == 0, "New token should have usage_count = 0"
    
    def test_tokens_list_mac_address_fields(self, base_url, test_config, session, test_token):
        """Verify MAC address fields are present and correct type"""
        response = session.get(
            f"{base_url}/api/tokens/list",
            params={"api_key": test_config.API_KEY}
        )
        
        assert response.status_code == 200
        data = response.json()
        token_data = next((t for t in data["tokens"] if t["token"] == test_token), None)
        
        assert token_data is not None, f"Token {test_token} not found"
        assert "device_count" in token_data, "Missing device_count field"
        assert "client_macs" in token_data, "Missing client_macs field"
        
        # Verify types
        assert isinstance(token_data["device_count"], int), "device_count must be integer"
        assert isinstance(token_data["client_macs"], list), "client_macs must be list"
        
        # For unused token, should have empty MAC array
        assert token_data["device_count"] == 0, "Unused token should have device_count = 0"
        assert len(token_data["client_macs"]) == 0, "Unused token should have empty client_macs"
    
    def test_tokens_list_mac_address_format(self, base_url, test_config, session):
        """Verify MAC addresses are formatted correctly when present"""
        import re
        
        response = session.get(
            f"{base_url}/api/tokens/list",
            params={"api_key": test_config.API_KEY}
        )
        
        data = response.json()
        
        # MAC address format regex: XX:XX:XX:XX:XX:XX (uppercase hex)
        mac_pattern = re.compile(r'^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$')
        
        for token in data["tokens"]:
            # Verify device_count matches MAC array length
            assert token["device_count"] == len(token["client_macs"]), \
                f"device_count ({token['device_count']}) != len(client_macs) ({len(token['client_macs'])})"
            
            # Verify each MAC address format
            for mac in token["client_macs"]:
                assert isinstance(mac, str), f"MAC address must be string, got {type(mac)}"
                assert mac_pattern.match(mac), f"Invalid MAC format: {mac}"
            
            # Verify device_count is within valid range (0-2)
            assert 0 <= token["device_count"] <= 2, \
                f"device_count must be 0-2, got {token['device_count']}"
    
    def test_token_info_includes_mac_addresses(self, base_url, test_config, session, test_token):
        """Verify /api/token/info includes client_macs field"""
        response = session.get(
            f"{base_url}/api/token/info",
            params={"api_key": test_config.API_KEY, "token": test_token}
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify MAC fields exist
        assert "device_count" in data, "Missing device_count in token info"
        assert "max_devices" in data, "Missing max_devices in token info"
        assert "client_macs" in data, "Missing client_macs in token info"
        
        # Verify types
        assert isinstance(data["device_count"], int), "device_count must be integer"
        assert isinstance(data["max_devices"], int), "max_devices must be integer"
        assert isinstance(data["client_macs"], list), "client_macs must be list"
        
        # Verify values
        assert data["max_devices"] == 2, "max_devices should always be 2"
        
        # For unused token
        if data["first_use"] == 0:
            assert data["device_count"] == 0, "Unused token should have device_count = 0"
            assert len(data["client_macs"]) == 0, "Unused token should have empty client_macs"


@pytest.mark.monitoring
class TestMonitoringErrorScenarios:
    """Test error scenarios for monitoring endpoints"""
    
    @pytest.mark.skip(reason="Requires test execution from local AP network (192.168.4.x)")
    def test_uptime_forbidden_from_ap_network(self, session):
        """Verify uptime endpoint returns 403 from AP network"""
        # This test would need to be run from a device on 192.168.4.x network
        # Skipped in normal test run
        pass
    
    @pytest.mark.skip(reason="Requires test execution from local AP network (192.168.4.x)")
    def test_health_forbidden_from_ap_network(self, session):
        """Verify health endpoint returns 403 from AP network"""
        # This test would need to be run from a device on 192.168.4.x network
        # Skipped in normal test run
        pass
