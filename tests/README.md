# ESP32 Captive Portal Integration Tests

Comprehensive integration test suite for the ESP32 Captive Portal with Token Management APIs.

## Overview

This test suite validates all API endpoints and system behavior of the ESP32 device at **192.168.0.120**. It includes:

- **Token Lifecycle Tests**: Token creation, querying, and basic operations
- **Token Management Tests**: Disable and extend operations  
- **Monitoring API Tests**: Uptime and health check endpoints
- **Error Scenario Tests**: All HTTP error codes (400, 401, 403, 404)
- **Integration Tests**: End-to-end workflows and stress testing

## Test Statistics

- **Total Test Files**: 5
- **Estimated Test Count**: 100+ tests
- **Coverage**: All 6 API endpoints
- **Test Categories**: 
  - `@pytest.mark.token_mgmt` - Token management operations
  - `@pytest.mark.monitoring` - Health and uptime monitoring
  - `@pytest.mark.error` - Error handling scenarios
  - `@pytest.mark.integration` - End-to-end workflows
  - `@pytest.mark.stress` - Load and performance tests

## Prerequisites

### 1. Device Requirements
- ESP32 device accessible at `http://192.168.0.120`
- Device must be connected to uplink network (not the AP network 192.168.4.x)
- Latest firmware flashed with API endpoints v3.0+

### 2. API Key
You need an API key to run the tests. Obtain it from:
- Admin panel: `http://192.168.4.1/admin` (when connected to ESP32 AP)
- Or set it programmatically during ESP32 setup

### 3. Python Environment
- Python 3.8 or higher
- pip package manager

## Installation

### 1. Clone/Navigate to Project
```bash
cd /Users/owner/iot/esp32-portal-mesh
```

### 2. Install Dependencies
```bash
pip install -r tests/requirements.txt
```

This installs:
- `pytest` - Test framework
- `requests` - HTTP client
- `pytest-html` - HTML test reports
- `pytest-timeout` - Test timeouts
- `pytest-sugar` - Improved output formatting

### 3. Set API Key (Optional)
Set the API key as an environment variable to avoid prompts:

**macOS/Linux:**
```bash
export ESP32_API_KEY="your-api-key-here"
```

**Windows (PowerShell):**
```powershell
$env:ESP32_API_KEY="your-api-key-here"
```

If not set, the test suite will prompt you to enter it when tests start.

## Running Tests

### Run All Tests
```bash
pytest tests/ -v
```

### Run Specific Test File
```bash
# Token lifecycle tests
pytest tests/test_token_lifecycle.py -v

# Token management tests
pytest tests/test_token_management.py -v

# Monitoring API tests
pytest tests/test_monitoring_apis.py -v

# Error scenario tests
pytest tests/test_error_scenarios.py -v

# Integration tests
pytest tests/test_integration.py -v
```

### Run Tests by Category
```bash
# Only token management tests
pytest tests/ -v -m token_mgmt

# Only monitoring tests
pytest tests/ -v -m monitoring

# Only error handling tests
pytest tests/ -v -m error

# Only integration tests
pytest tests/ -v -m integration

# Stress/load tests
pytest tests/ -v -m stress
```

### Run with Coverage
```bash
pytest tests/ --cov=. --cov-report=html
# Open htmlcov/index.html in browser
```

### Generate HTML Report
```bash
pytest tests/ --html=test_report.html --self-contained-html
# Open test_report.html in browser
```

### Run with Detailed Output
```bash
# Show print statements
pytest tests/ -v -s

# Show test durations
pytest tests/ -v --durations=10

# Stop on first failure
pytest tests/ -v -x
```

### Run Failed Tests Only
```bash
# After a test run with failures
pytest tests/ --lf  # Last failed
pytest tests/ --ff  # Failed first
```

## Test Configuration

Tests are configured in `tests/config.py`:

```python
DEVICE_IP = "192.168.0.120"           # ESP32 device IP
TEST_TOKEN_DURATION = 30              # Test token duration (minutes)
TEST_BANDWIDTH_DOWN = 100             # Download bandwidth (MB)
TEST_BANDWIDTH_UP = 50                # Upload bandwidth (MB)
MAX_ACTIVE_TOKENS = 230               # Device capacity
MIN_FREE_HEAP = 50000                 # Minimum heap threshold
```

Modify these values to match your testing requirements.

## Test Fixtures

The test suite uses pytest fixtures for automatic resource management:

- **`test_token`** - Creates a token, yields it, auto-cleanup after test
- **`multiple_test_tokens(n)`** - Creates N tokens with cleanup
- **`initial_device_health`** - Baseline health metrics for comparison
- **`session`** - Configured requests session with timeout
- **`verify_api_key`** - Prompts for API key if not in environment

## API Endpoints Tested

### Token Management (Requires API Key + Uplink Network)
- `POST /api/token` - Create new token
- `GET /api/token/info` - Query token information
- `POST /api/token/disable` - Disable/delete token
- `POST /api/token/extend` - Extend token duration

### Monitoring (Public Access)
- `GET /api/uptime` - Device uptime with microsecond precision
- `GET /api/health` - Comprehensive health metrics

## Expected Test Results

### Successful Run Output
```
tests/test_monitoring_apis.py::TestUptimeAPI ........        [ 8%]
tests/test_monitoring_apis.py::TestHealthAPI ..........      [18%]
tests/test_token_lifecycle.py::TestTokenCreation ......      [24%]
tests/test_token_lifecycle.py::TestTokenInfo ....           [28%]
tests/test_token_management.py::TestTokenDisable ...        [31%]
tests/test_token_management.py::TestTokenExtend .....       [36%]
tests/test_error_scenarios.py::TestAuthenticationErrors ... [39%]
tests/test_error_scenarios.py::TestNotFoundErrors ....      [43%]
tests/test_error_scenarios.py::TestBadRequestErrors ....... [50%]
tests/test_integration.py::TestCompleteWorkflows ...        [53%]
tests/test_integration.py::TestLoadScenarios ....           [57%]

======================== 100 passed in 45.23s =========================
```

### Test Duration
- **Full suite**: ~1-2 minutes
- **Individual files**: 10-20 seconds each
- **Integration tests**: 20-30 seconds
- **Stress tests**: 30-60 seconds

## Troubleshooting

### Device Not Accessible
```
requests.exceptions.ConnectionError: Failed to establish connection
```
**Solution**: 
- Verify device is powered on and accessible at 192.168.0.120
- Check network connectivity: `ping 192.168.0.120`
- Ensure you're on the uplink network, not the AP network

### 403 Forbidden Errors
```
assert response.status_code == 200
AssertionError: Expected 200, got 403
```
**Solution**:
- Token management APIs only work from uplink network
- Connect to the same network as the ESP32's uplink connection
- Tests marked with `@pytest.mark.skip` require AP network (192.168.4.x)

### 401 Unauthorized Errors
```
data["error"] == "Invalid API key"
```
**Solution**:
- Verify API key is correct
- Get API key from http://192.168.4.1/admin
- Set environment variable: `export ESP32_API_KEY="your-key"`

### Import Errors (pytest not found)
```
ImportError: No module named 'pytest'
```
**Solution**:
```bash
pip install -r tests/requirements.txt
```

### Token Capacity Errors
```
pytest.skip: Not enough capacity (only 5 slots available)
```
**Solution**:
- Device has MAX_TOKENS=230 capacity
- Clean up existing tokens via admin panel or API
- Restart device to clear all tokens

### Memory Stability Test Failures
```
AssertionError: Heap changed by 25000 bytes
```
**Solution**:
- Device may be under load from other operations
- Reboot device before running tests
- Run tests in isolation: `pytest tests/test_integration.py::test_memory_stability`

## Test Cleanup

Tests automatically clean up created tokens using fixtures. If tests are interrupted:

### Manual Cleanup via API
```bash
# List all tokens (requires API key)
curl "http://192.168.0.120/api/health"

# Disable specific token
curl -X POST http://192.168.0.120/api/token/disable \
  -d "api_key=YOUR_API_KEY" \
  -d "token=TOKEN_TO_DELETE"
```

### Cleanup via Device Reboot
Tokens are stored in NVS and persist across reboots, but you can:
1. Access admin panel: http://192.168.4.1/admin
2. Manually disable tokens
3. Or wait for automatic cleanup (every 30 seconds)

## Continuous Integration

### GitHub Actions Example
```yaml
name: ESP32 Integration Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - run: pip install -r tests/requirements.txt
      - run: pytest tests/ -v
        env:
          ESP32_API_KEY: ${{ secrets.ESP32_API_KEY }}
```

## Development

### Adding New Tests

1. Create test file in `tests/` directory
2. Import required fixtures from `conftest.py`
3. Use appropriate pytest markers
4. Follow naming convention: `test_*.py`

Example:
```python
import pytest

@pytest.mark.token_mgmt
def test_new_feature(base_url, session, test_config, test_token):
    """Test description"""
    response = session.get(
        f"{base_url}/api/some_endpoint",
        params={"token": test_token}
    )
    assert response.status_code == 200
```

### Test Markers
```python
@pytest.mark.token_mgmt   # Token operations
@pytest.mark.monitoring   # Health/uptime
@pytest.mark.error        # Error scenarios
@pytest.mark.integration  # End-to-end
@pytest.mark.stress       # Load testing
@pytest.mark.timing       # Time-sensitive tests
@pytest.mark.regression   # Regression tests
@pytest.mark.edge_case    # Edge cases
```

## API Documentation

Full API documentation: See `API-DOCUMENTATION.md` in project root.

## Version History

- **v3.0** (2025-12-10)
  - Added monitoring endpoints (uptime, health)
  - Increased token capacity to 230
  - Automatic cleanup every 30 seconds
  - HTTP response refactoring
  - Comprehensive test suite

- **v2.0** (Previous)
  - Token management APIs
  - NVS persistence
  - Statistics tracking

## Support

For issues or questions:
1. Check API documentation: `API-DOCUMENTATION.md`
2. Review test output and error messages
3. Verify device firmware version
4. Check device logs via serial connection

## License

Part of ESP32 Captive Portal project. See main project LICENSE.
