"""
End-to-End Integration Tests

Complete workflows testing multiple endpoints together.
Validates real-world scenarios and system behavior.
"""

import pytest
import time


@pytest.mark.integration
class TestCompleteWorkflows:
    """Test complete end-to-end workflows"""
    
    def test_full_token_lifecycle(self, base_url, session, test_config):
        """Complete token lifecycle: create -> query -> use -> extend -> disable"""
        # 1. Check initial device health
        health_response = session.get(f"{base_url}/api/health")
        assert health_response.status_code == 200
        initial_health = health_response.json()
        initial_token_count = initial_health["active_tokens"]
        
        # 2. Create token
        create_response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.TEST_TOKEN_DURATION,
                "bandwidth_down": test_config.TEST_BANDWIDTH_DOWN,
                "bandwidth_up": test_config.TEST_BANDWIDTH_UP
            }
        )
        
        assert create_response.status_code == 200
        create_data = create_response.json()
        assert create_data["success"] is True
        token = create_data["token"]
        
        # 3. Verify token count increased
        health_response2 = session.get(f"{base_url}/api/health")
        new_health = health_response2.json()
        assert new_health["active_tokens"] == initial_token_count + 1
        
        # 4. Query token info
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
        assert info_data["token"] == token
        assert info_data["duration_minutes"] == test_config.TEST_TOKEN_DURATION
        
        # 5. Reset token (extend endpoint)
        extend_response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        
        assert extend_response.status_code == 200
        extend_data = extend_response.json()
        assert extend_data["new_duration_minutes"] == test_config.TEST_TOKEN_DURATION  # Duration unchanged
        
        # 6. Verify reset in token info (duration same, usage reset)
        info_response2 = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        
        info_data2 = info_response2.json()
        assert info_data2["duration_minutes"] == test_config.TEST_TOKEN_DURATION  # Duration unchanged
        assert info_data2["usage_count"] == 0  # Usage reset
        
        # 7. Disable token
        disable_response = session.post(
            f"{base_url}/api/token/disable",
            data={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        
        assert disable_response.status_code == 200
        
        # 8. Verify token count decreased
        health_response3 = session.get(f"{base_url}/api/health")
        final_health = health_response3.json()
        assert final_health["active_tokens"] == initial_token_count
        
        # 9. Verify token no longer exists
        info_response3 = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        
        assert info_response3.status_code == 404
    
    def test_multiple_token_management(self, base_url, session, test_config):
        """Manage multiple tokens concurrently"""
        # Create 10 tokens
        tokens = []
        
        for i in range(10):
            response = session.post(
                f"{base_url}/api/token",
                data={
                    "api_key": test_config.API_KEY,
                    "duration": test_config.TEST_TOKEN_DURATION + (i * 10),
                    "bandwidth_down": 100 * (i + 1),
                    "bandwidth_up": 50 * (i + 1)
                }
            )
            
            assert response.status_code == 200
            tokens.append(response.json()["token"])
        
        # Verify all tokens exist
        for token in tokens:
            response = session.get(
                f"{base_url}/api/token/info",
                params={
                    "api_key": test_config.API_KEY,
                    "token": token
                }
            )
            assert response.status_code == 200
        
        # Reset first 5 tokens
        for i in range(5):
            response = session.post(
                f"{base_url}/api/token/extend",
                data={
                    "api_key": test_config.API_KEY,
                    "token": tokens[i]
                }
            )
            assert response.status_code == 200
        
        # Disable last 5 tokens
        for i in range(5, 10):
            response = session.post(
                f"{base_url}/api/token/disable",
                data={
                    "api_key": test_config.API_KEY,
                    "token": tokens[i]
                }
            )
            assert response.status_code == 200
        
        # Verify first 5 still exist and extended
        for i in range(5):
            response = session.get(
                f"{base_url}/api/token/info",
                params={
                    "api_key": test_config.API_KEY,
                    "token": tokens[i]
                }
            )
            assert response.status_code == 200
            data = response.json()
            expected_duration = test_config.TEST_TOKEN_DURATION + (i * 10) + 30
            assert data["duration_minutes"] == expected_duration
        
        # Verify last 5 are gone
        for i in range(5, 10):
            response = session.get(
                f"{base_url}/api/token/info",
                params={
                    "api_key": test_config.API_KEY,
                    "token": tokens[i]
                }
            )
            assert response.status_code == 404
        
        # Cleanup remaining tokens
        for i in range(5):
            session.post(
                f"{base_url}/api/token/disable",
                data={"api_key": test_config.API_KEY, "token": tokens[i]}
            )
    
    def test_monitoring_with_token_operations(self, base_url, session, test_config):
        """Monitor device health during token operations"""
        # Get initial metrics
        initial_health = session.get(f"{base_url}/api/health").json()
        initial_uptime = session.get(f"{base_url}/api/uptime").json()
        
        initial_token_count = initial_health["active_tokens"]
        initial_free_heap = initial_health["free_heap_bytes"]
        
        # Perform operations
        tokens = []
        for _ in range(5):
            response = session.post(
                f"{base_url}/api/token",
                data={
                    "api_key": test_config.API_KEY,
                    "duration": test_config.TEST_TOKEN_DURATION,
                    "bandwidth_down": 0,
                    "bandwidth_up": 0
                }
            )
            tokens.append(response.json()["token"])
        
        # Check health after creation
        mid_health = session.get(f"{base_url}/api/health").json()
        assert mid_health["active_tokens"] == initial_token_count + 5
        
        # Memory should be stable (allow 10KB variation)
        heap_diff = abs(mid_health["free_heap_bytes"] - initial_free_heap)
        assert heap_diff < 10000, f"Heap changed by {heap_diff} bytes"
        
        # Uptime should increase
        mid_uptime = session.get(f"{base_url}/api/uptime").json()
        assert mid_uptime["uptime_seconds"] >= initial_uptime["uptime_seconds"]
        
        # Cleanup
        for token in tokens:
            session.post(
                f"{base_url}/api/token/disable",
                data={"api_key": test_config.API_KEY, "token": token}
            )
        
        # Verify cleanup
        final_health = session.get(f"{base_url}/api/health").json()
        assert final_health["active_tokens"] == initial_token_count


@pytest.mark.integration
@pytest.mark.stress
class TestLoadScenarios:
    """Test system under load"""
    
    def test_rapid_token_creation(self, base_url, session, test_config):
        """Create many tokens rapidly"""
        tokens = []
        
        # Create 20 tokens as fast as possible
        for i in range(20):
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
            tokens.append(response.json()["token"])
        
        # Verify all unique
        assert len(tokens) == len(set(tokens))
        
        # Verify all exist
        for token in tokens:
            response = session.get(
                f"{base_url}/api/token/info",
                params={
                    "api_key": test_config.API_KEY,
                    "token": token
                }
            )
            assert response.status_code == 200
        
        # Cleanup
        for token in tokens:
            session.post(
                f"{base_url}/api/token/disable",
                data={"api_key": test_config.API_KEY, "token": token}
            )
    
    def test_rapid_token_queries(self, base_url, session, test_config, test_token):
        """Query token info repeatedly"""
        # Query 50 times rapidly
        for _ in range(50):
            response = session.get(
                f"{base_url}/api/token/info",
                params={
                    "api_key": test_config.API_KEY,
                    "token": test_token
                }
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["token"] == test_token
    
    def test_rapid_monitoring_queries(self, base_url, session):
        """Query monitoring endpoints repeatedly"""
        # Query 100 times rapidly
        for _ in range(100):
            health_response = session.get(f"{base_url}/api/health")
            uptime_response = session.get(f"{base_url}/api/uptime")
            
            assert health_response.status_code == 200
            assert uptime_response.status_code == 200
    
    def test_token_capacity_limit(self, base_url, session, test_config):
        """Test approaching maximum token capacity"""
        # Get current token count
        health = session.get(f"{base_url}/api/health").json()
        current_count = health["active_tokens"]
        
        # Calculate how many tokens we can create
        available_slots = test_config.MAX_ACTIVE_TOKENS - current_count
        
        # Don't exceed capacity, test with reasonable number
        tokens_to_create = min(50, available_slots)
        
        if tokens_to_create < 10:
            pytest.skip(f"Not enough capacity (only {available_slots} slots available)")
        
        tokens = []
        for i in range(tokens_to_create):
            # Add delay every 5 tokens to avoid overwhelming device
            if i > 0 and i % 5 == 0:
                time.sleep(0.3)  # 300ms pause every 5 tokens
            
            response = session.post(
                f"{base_url}/api/token",
                data={
                    "api_key": test_config.API_KEY,
                    "duration": test_config.TEST_TOKEN_DURATION,
                    "bandwidth_down": 0,
                    "bandwidth_up": 0
                }
            )
            
            if response.status_code == 200:
                tokens.append(response.json()["token"])
            else:
                # Might hit capacity limit
                break
        
        # Verify health shows increased count
        final_health = session.get(f"{base_url}/api/health").json()
        assert final_health["active_tokens"] >= current_count + len(tokens)
        
        # Cleanup with throttling
        for i, token in enumerate(tokens):
            if i > 0 and i % 5 == 0:
                time.sleep(0.2)  # 200ms pause every 5 deletions
            
            session.post(
                f"{base_url}/api/token/disable",
                data={"api_key": test_config.API_KEY, "token": token}
            )


@pytest.mark.integration
@pytest.mark.timing
class TestTimingAndConsistency:
    """Test timing-related behavior and data consistency"""
    
    def test_uptime_consistency_across_calls(self, base_url, session):
        """Uptime should be consistent across multiple calls"""
        # Get uptime 3 times with small delays
        uptimes = []
        
        for _ in range(3):
            response = session.get(f"{base_url}/api/uptime")
            uptimes.append(response.json()["uptime_seconds"])
            time.sleep(0.5)
        
        # Each should be >= previous
        for i in range(1, len(uptimes)):
            assert uptimes[i] >= uptimes[i-1], "Uptime should never decrease"
    
    def test_health_and_uptime_consistency(self, base_url, session):
        """Health and uptime endpoints should report consistent values"""
        # Get both simultaneously
        health = session.get(f"{base_url}/api/health").json()
        uptime = session.get(f"{base_url}/api/uptime").json()
        
        # Uptime should match (within 1 second tolerance)
        health_uptime = health["uptime_seconds"]
        uptime_seconds = uptime["uptime_seconds"]
        
        assert abs(health_uptime - uptime_seconds) <= 1, \
            f"Health uptime ({health_uptime}) and uptime ({uptime_seconds}) differ"
    
    def test_token_timestamps_valid(self, base_url, session, test_config, test_token):
        """Token timestamps should be valid and consistent"""
        info = session.get(
            f"{base_url}/api/token/info",
            params={
                "api_key": test_config.API_KEY,
                "token": test_token
            }
        ).json()
        
        # Created should be non-zero
        assert info["created"] > 0
        
        # First use should be 0 for unused token
        assert info["first_use"] == 0
        
        # Expires_at should be created + duration
        expected_expiry = info["created"] + (info["duration_minutes"] * 60)
        assert info["expires_at"] == expected_expiry
    
    def test_time_sync_status(self, base_url, session):
        """Health should report time sync status"""
        health = session.get(f"{base_url}/api/health").json()
        
        # time_synced should be boolean
        assert isinstance(health["time_synced"], bool)
        
        # If time is synced, timestamps should be reasonable
        if health["time_synced"]:
            assert health["uptime_seconds"] > 0


@pytest.mark.integration
@pytest.mark.regression
class TestRegressionScenarios:
    """Test scenarios that have caused issues in the past"""
    
    def test_double_disable_idempotency(self, base_url, session, test_config):
        """Disabling token twice should not cause errors"""
        # Create token
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.TEST_TOKEN_DURATION,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        token = response.json()["token"]
        
        # Disable first time
        response1 = session.post(
            f"{base_url}/api/token/disable",
            data={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        assert response1.status_code == 200
        
        # Disable second time
        response2 = session.post(
            f"{base_url}/api/token/disable",
            data={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        assert response2.status_code == 404  # Not an error, just not found
    
    def test_extend_disabled_token_fails(self, base_url, session, test_config):
        """Extending disabled token should fail gracefully"""
        # Create and disable token
        response = session.post(
            f"{base_url}/api/token",
            data={
                "api_key": test_config.API_KEY,
                "duration": test_config.TEST_TOKEN_DURATION,
                "bandwidth_down": 0,
                "bandwidth_up": 0
            }
        )
        token = response.json()["token"]
        
        session.post(
            f"{base_url}/api/token/disable",
            data={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        
        # Try to reset disabled token
        response = session.post(
            f"{base_url}/api/token/extend",
            data={
                "api_key": test_config.API_KEY,
                "token": token
            }
        )
        
        assert response.status_code == 404
    
    def test_memory_stability_under_operations(self, base_url, session, test_config):
        """Memory should remain stable during many operations"""
        # Get initial heap
        initial_health = session.get(f"{base_url}/api/health").json()
        initial_heap = initial_health["free_heap_bytes"]
        
        # Perform 20 create/disable cycles with realistic timing
        for i in range(20):
            # Add delay every 5 operations
            if i > 0 and i % 5 == 0:
                time.sleep(0.3)  # 300ms pause every 5 cycles
            
            response = session.post(
                f"{base_url}/api/token",
                data={
                    "api_key": test_config.API_KEY,
                    "duration": test_config.TEST_TOKEN_DURATION,
                    "bandwidth_down": 0,
                    "bandwidth_up": 0
                }
            )
            token = response.json()["token"]
            
            # Small delay between create and disable
            time.sleep(0.05)  # 50ms
            
            session.post(
                f"{base_url}/api/token/disable",
                data={"api_key": test_config.API_KEY, "token": token}
            )
        
        # Check final heap
        final_health = session.get(f"{base_url}/api/health").json()
        final_heap = final_health["free_heap_bytes"]
        
        # Allow 20KB variation (should be much less)
        heap_diff = abs(final_heap - initial_heap)
        assert heap_diff < 20000, \
            f"Heap changed by {heap_diff} bytes (initial: {initial_heap}, final: {final_heap})"
        
        # Should be above minimum threshold
        assert final_heap >= test_config.MIN_FREE_HEAP
