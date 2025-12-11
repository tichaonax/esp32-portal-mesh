# ESP32 Portal Token API Documentation

## Overview
The Token API allows third-party applications to request access tokens for guest WiFi access. All API requests must be authenticated using an API key and can only be accessed from the uplink network (not from the AP network 192.168.4.x).

## Base URL
The API is accessible from the uplink IP address of the ESP32 device. You can find the uplink IP in the admin dashboard.

Example: `http://192.168.0.x` (where x is the device's DHCP-assigned IP)

## Authentication
All API requests require an API key passed as a form parameter.

### Obtaining an API Key
1. Access the admin dashboard at `http://192.168.4.1/admin`
2. Login with your admin password
3. Navigate to the "API Management" section
4. Copy the displayed API key
5. To regenerate the key, click "Regenerate API Key"

**Important:** Keep your API key secure. Anyone with the key can generate tokens.

## Endpoints

### POST /api/token
Create a new guest access token with specified duration and bandwidth limits.

#### Request

**Content-Type:** `application/x-www-form-urlencoded`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_key` | string | Yes | Your 32-character API key |
| `duration` | integer | Yes | Token duration in minutes (min: 30, max: 43200) |
| `bandwidth_down` | integer | No | Download limit in MB (0 = unlimited) |
| `bandwidth_up` | integer | No | Upload limit in MB (0 = unlimited) |

**Duration Limits:**
- Minimum: 30 minutes
- Maximum: 43,200 minutes (30 days)

**Bandwidth Limits:**
- Set to 0 or omit for unlimited bandwidth
- Token expires when either time OR bandwidth limit is reached

**Device Limit:**
- Each token supports maximum 2 simultaneous devices
- Devices are tracked by MAC address

#### Example Requests

**cURL:**
```bash
curl -X POST http://192.168.0.100/api/token \
  -d "api_key=abcd1234efgh5678ijkl9012mnop3456" \
  -d "duration=120" \
  -d "bandwidth_down=500" \
  -d "bandwidth_up=100"
```

**Python:**
```python
import requests

url = "http://192.168.0.100/api/token"
data = {
    "api_key": "abcd1234efgh5678ijkl9012mnop3456",
    "duration": 120,  # 2 hours
    "bandwidth_down": 500,  # 500 MB download
    "bandwidth_up": 100  # 100 MB upload
}

response = requests.post(url, data=data)
print(response.json())
```

**JavaScript (Node.js):**
```javascript
const axios = require('axios');

const params = new URLSearchParams({
    api_key: 'abcd1234efgh5678ijkl9012mnop3456',
    duration: '120',
    bandwidth_down: '500',
    bandwidth_up: '100'
});

axios.post('http://192.168.0.100/api/token', params)
    .then(response => console.log(response.data))
    .catch(error => console.error(error.response.data));
```

#### Success Response

**Code:** `200 OK`

**Content:**
```json
{
    "success": true,
    "token": "A3K9M7P2",
    "duration_minutes": 120,
    "bandwidth_down_mb": 500,
    "bandwidth_up_mb": 100
}
```

#### Error Responses

**Invalid API Key**

**Code:** `401 Unauthorized`
```json
{
    "success": false,
    "error": "Invalid API key"
}
```

**Request from AP Network**

**Code:** `403 Forbidden`
```json
{
    "error": "API only accessible from uplink network"
}
```

**Invalid Parameters**

**Code:** `400 Bad Request`
```json
{
    "success": false,
    "error": "Invalid parameters or token limit reached"
}
```

Possible reasons:
- Duration outside allowed range (30-43200 minutes)
- Token storage limit reached (max 230 tokens)
- Missing required parameters

**Missing Parameters**

**Code:** `400 Bad Request`
```json
{
    "success": false,
    "error": "Missing required parameters"
}
```

---

### POST /api/token/disable
Disable a previously issued token, preventing further use. Useful for revoking access or canceling unused tokens.

#### Request

**Content-Type:** `application/x-www-form-urlencoded`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_key` | string | Yes | Your 32-character API key |
| `token` | string | Yes | The 8-character token to disable |

#### Example Requests

**cURL:**
```bash
curl -X POST http://192.168.0.100/api/token/disable \
  -d "api_key=abcd1234efgh5678ijkl9012mnop3456" \
  -d "token=A3K9M7P2"
```

**Python:**
```python
import requests

url = "http://192.168.0.100/api/token/disable"
data = {
    "api_key": "abcd1234efgh5678ijkl9012mnop3456",
    "token": "A3K9M7P2"
}

response = requests.post(url, data=data)
print(response.json())
```

#### Success Response

**Code:** `200 OK`
```json
{
    "success": true,
    "message": "Token disabled successfully"
}
```

#### Error Responses

**Token Not Found**

**Code:** `404 Not Found`
```json
{
    "success": false,
    "error": "Token not found or already disabled",
    "error_code": "TOKEN_NOT_FOUND"
}
```

This error occurs when:
- The token doesn't exist
- The token has already been disabled
- The token was entered incorrectly

**Other Errors:** Same as `/api/token` endpoint (401, 403, 400)

---

### GET /api/token/info
Retrieve detailed information about a token including usage statistics, expiration status, and bandwidth consumption.

#### Request

**Method:** GET

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_key` | string | Yes | Your 32-character API key |
| `token` | string | Yes | The 8-character token to query |

#### Example Requests

**cURL:**
```bash
curl -X GET "http://192.168.0.100/api/token/info?api_key=abcd1234efgh5678ijkl9012mnop3456&token=A3K9M7P2"
```

**Python:**
```python
import requests

url = "http://192.168.0.100/api/token/info"
params = {
    "api_key": "abcd1234efgh5678ijkl9012mnop3456",
    "token": "A3K9M7P2"
}

response = requests.get(url, params=params)
print(response.json())
```

**JavaScript:**
```javascript
const axios = require('axios');

axios.get('http://192.168.0.100/api/token/info', {
    params: {
        api_key: 'abcd1234efgh5678ijkl9012mnop3456',
        token: 'A3K9M7P2'
    }
})
.then(response => console.log(response.data))
.catch(error => console.error(error.response.data));
```

#### Success Response

**Code:** `200 OK`
```json
{
    "success": true,
    "token": "A3K9M7P2",
    "status": "active",
    "created": 1702123456,
    "first_use": 1702124000,
    "duration_minutes": 120,
    "expires_at": 1702131200,
    "remaining_seconds": 3600,
    "bandwidth_down_mb": 500,
    "bandwidth_up_mb": 100,
    "bandwidth_used_down_mb": 150,
    "bandwidth_used_up_mb": 25,
    "usage_count": 12,
    "device_count": 1,
    "max_devices": 2
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Token status: "unused", "active", or "expired" |
| `created` | integer | Unix timestamp when token was created |
| `first_use` | integer | Unix timestamp when first used (0 if unused) |
| `duration_minutes` | integer | Total token duration in minutes |
| `expires_at` | integer | Unix timestamp when token expires (0 if unused) |
| `remaining_seconds` | integer | Seconds until expiration (0 if expired/unused) |
| `bandwidth_down_mb` | integer | Download limit in MB (0 = unlimited) |
| `bandwidth_up_mb` | integer | Upload limit in MB (0 = unlimited) |
| `bandwidth_used_down_mb` | integer | Downloaded data so far |
| `bandwidth_used_up_mb` | integer | Uploaded data so far |
| `usage_count` | integer | Number of times token has been used |
| `device_count` | integer | Number of devices currently using token |
| `max_devices` | integer | Maximum allowed devices (always 2) |

#### Error Responses

**Token Not Found**

**Code:** `404 Not Found`
```json
{
    "success": false,
    "error": "Token not found",
    "error_code": "TOKEN_NOT_FOUND"
}
```

This error occurs when:
- The token doesn't exist in the system
- The token has been disabled
- The token was entered incorrectly

**Other Errors:** Same as `/api/token` endpoint (401, 403, 400)

---

### POST /api/token/extend
Extend/renew a token by resetting its usage timer and bandwidth counters. This effectively gives the token a fresh start with the same original duration and bandwidth limits. Perfect for "top-up" or subscription renewal scenarios.

#### Request

**Content-Type:** `application/x-www-form-urlencoded`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_key` | string | Yes | Your 32-character API key |
| `token` | string | Yes | The 8-character token to extend |

**Important Notes:**
- Resets `first_use` to current time, restarting the duration countdown
- Resets bandwidth usage counters to 0
- Keeps the same `duration_minutes` and bandwidth limits as original
- Resets `usage_count` to 0
- Does NOT remove device bindings (same devices can continue using)

#### Example Requests

**cURL:**
```bash
curl -X POST http://192.168.0.100/api/token/extend \
  -d "api_key=abcd1234efgh5678ijkl9012mnop3456" \
  -d "token=A3K9M7P2"
```

**Python:**
```python
import requests

url = "http://192.168.0.100/api/token/extend"
data = {
    "api_key": "abcd1234efgh5678ijkl9012mnop3456",
    "token": "A3K9M7P2"
}

response = requests.post(url, data=data)
print(response.json())
```

**JavaScript:**
```javascript
const axios = require('axios');

const params = new URLSearchParams({
    api_key: 'abcd1234efgh5678ijkl9012mnop3456',
    token: 'A3K9M7P2'
});

axios.post('http://192.168.0.100/api/token/extend', params)
    .then(response => console.log(response.data))
    .catch(error => console.error(error.response.data));
```

#### Success Response

**Code:** `200 OK`
```json
{
    "success": true,
    "message": "Token extended successfully",
    "token": "A3K9M7P2",
    "duration_minutes": 120,
    "new_expires_at": 1702138400,
    "bandwidth_down_mb": 500,
    "bandwidth_up_mb": 100
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `message` | string | Confirmation message |
| `token` | string | The extended token |
| `duration_minutes` | integer | Token duration (unchanged from original) |
| `new_expires_at` | integer | New expiration timestamp (current time + duration) |
| `bandwidth_down_mb` | integer | Download limit (unchanged) |
| `bandwidth_up_mb` | integer | Upload limit (unchanged) |

#### Error Responses

**Token Not Found**

**Code:** `404 Not Found`
```json
{
    "success": false,
    "error": "Token not found or has been disabled",
    "error_code": "TOKEN_NOT_FOUND"
}
```

This error occurs when:
- The token doesn't exist in the system
- The token has been disabled via `/api/token/disable`
- The token was entered incorrectly

**Use Case:** Your application should handle this gracefully by:
- Checking if the token was disabled
- Offering to create a new token instead
- Informing the user the token is no longer valid

**Other Errors:** Same as `/api/token` endpoint (401, 403, 400)

---

### GET /api/uptime
Get the system uptime since last reboot. This endpoint does not require authentication and is useful for monitoring device availability.

#### Request

**Method:** GET

**Authentication:** None required

**Query Parameters:** None

#### Example Requests

**cURL:**
```bash
curl -X GET "http://192.168.0.100/api/uptime"
```

**Python:**
```python
import requests

response = requests.get('http://192.168.0.100/api/uptime')
print(response.json())
```

#### Success Response

**Code:** `200 OK`

```json
{
    "success": true,
    "uptime_seconds": 12345,
    "uptime_microseconds": 12345678901
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `success` | boolean | Always true for successful requests |
| `uptime_seconds` | integer | System uptime in seconds |
| `uptime_microseconds` | integer | System uptime in microseconds (higher precision) |

#### Error Responses

**Request from AP Network**

**Code:** `403 Forbidden`
```json
{
    "error": "API only accessible from uplink network"
}
```

---

### GET /api/health
Get comprehensive device health status including uptime, time sync, token count, and memory usage. This endpoint does not require authentication and follows standard health check patterns for monitoring systems.

#### Request

**Method:** GET

**Authentication:** None required

**Query Parameters:** None

#### Example Requests

**cURL:**
```bash
curl -X GET "http://192.168.0.100/api/health"
```

**Python:**
```python
import requests

response = requests.get('http://192.168.0.100/api/health')
print(response.json())
```

#### Success Response

**Code:** `200 OK`

```json
{
    "success": true,
    "status": "healthy",
    "uptime_seconds": 12345,
    "time_synced": true,
    "last_time_sync": 1702345678,
    "current_time": 1702358023,
    "active_tokens": 5,
    "max_tokens": 230,
    "free_heap_bytes": 245760
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `success` | boolean | Always true for successful requests |
| `status` | string | Overall health status ("healthy") |
| `uptime_seconds` | integer | System uptime in seconds since boot |
| `time_synced` | boolean | Whether SNTP time sync is complete |
| `last_time_sync` | integer | Unix timestamp of last SNTP sync (0 if never) |
| `current_time` | integer | Current Unix timestamp |
| `active_tokens` | integer | Number of currently active tokens |
| `max_tokens` | integer | Maximum token capacity (230) |
| `free_heap_bytes` | integer | Available RAM in bytes |

#### Error Responses

**Request from AP Network**

**Code:** `403 Forbidden`
```json
{
    "error": "API only accessible from uplink network"
}
```

---

## Error Code Reference

All API endpoints may return the following standard error codes:

| Error Code | HTTP Status | Description | Resolution |
|------------|-------------|-------------|------------|
| `TOKEN_NOT_FOUND` | 404 | Token doesn't exist or has been disabled | Check token spelling, verify it wasn't disabled, or create a new token |
| N/A (Invalid API key) | 401 | API key is incorrect | Verify API key from admin dashboard, regenerate if needed |
| N/A (Forbidden) | 403 | Request from guest network | Make API calls from uplink network only |
| N/A (Bad Request) | 400 | Missing or invalid parameters | Check required parameters and value formats |

### Handling TOKEN_NOT_FOUND

When you receive a `TOKEN_NOT_FOUND` error, your application should:

1. **For `/api/token/info`**: Notify that the token is invalid or has been removed
2. **For `/api/token/disable`**: Treat as success (token is already disabled)
3. **For `/api/token/extend`**: Offer to create a new token instead of extending

**Example Error Handling (Python):**
```python
def extend_token_with_fallback(api_key, token):
    """Try to extend token, create new one if it doesn't exist"""
    try:
        response = requests.post(
            'http://192.168.0.100/api/token/extend',
            data={'api_key': api_key, 'token': token}
        )
        
        if response.status_code == 404:
            # Token not found - create a new one instead
            print(f"Token {token} not found, creating new token...")
            return create_new_token(api_key, duration=120)
        
        response.raise_for_status()
        return response.json()
        
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None
```

---

**Missing Parameters**

**Code:** `400 Bad Request`
```json
{
    "success": false,
    "error": "Missing required parameters"
}
```

## Token Usage

### Guest Login Process
1. Guest connects to ESP32-Guest-Portal WiFi
2. Guest navigates to any HTTP website (gets redirected)
3. Guest enters the 8-character token on the portal page
4. Token is validated and guest gets internet access

### Token Properties
- **Format:** 8 uppercase alphanumeric characters (excludes confusing chars like O, 0, I, l)
- **First Use:** Timer starts when token is first used, not when created
- **Device Binding:** Token remembers which devices used it (max 2)
- **Expiration:** Token expires when:
  - Time limit is reached (from first use)
  - Download bandwidth limit is reached
  - Upload bandwidth limit is reached

### Token States
- **Created:** Token generated but never used
- **Active:** Token in use, not expired
- **Expired:** Time or bandwidth limit reached

## Admin Dashboard Features

### Quick Token Generation
The admin dashboard provides a simplified token generation form:
- **Location:** http://192.168.4.1/admin (AP network only)
- **Duration Options:** 30min, 1h, 2h, 4h, 8h, 12h
- **Bandwidth:** Unlimited (for quick generation)
- **No API Key Required:** Admin authentication only

### API Key Management
- **View API Key:** Displayed in admin dashboard
- **Regenerate Key:** Creates new key, invalidates old one
- **Security:** Only accessible when logged into admin

### Session Management
- **Auto-Logout:** 5 minutes of inactivity
- **Manual Logout:** Button in dashboard header
- **Session Tracking:** All admin actions update activity timestamp

### Password Management
- **Change Password:** In admin dashboard
- **Requirements:** Minimum 6 characters
- **Verification:** Must enter old password
- **Storage:** Securely stored in NVS flash

## Network Requirements

### API Access Rules
- **Allowed:** Requests from uplink network (e.g., 192.168.0.x)
- **Blocked:** Requests from AP network (192.168.4.x)
- **Reason:** Security - prevents guests from creating their own tokens

### Admin Access Rules
- **Admin Dashboard:** Only accessible from AP network (192.168.4.x)
- **WiFi Config:** Requires admin password
- **API Endpoints:** Require admin session login

## Rate Limiting
Currently no rate limiting is implemented. Consider implementing rate limiting in your application layer if needed.

## Best Practices

### Security
1. **Protect API Key:** Store securely, never commit to version control
2. **HTTPS:** Consider using a reverse proxy with HTTPS for production
3. **Regenerate Keys:** Periodically regenerate API keys
4. **Monitor Usage:** Track token creation patterns for abuse

### Token Management
1. **Set Appropriate Limits:** Match duration/bandwidth to expected usage
2. **Automatic Cleanup:** Expired tokens are automatically removed every 30 seconds (SNTP sync)
3. **Storage Capacity:** Max 230 active tokens supported (automatically cleaned up when expired)
4. **Use Extend for Renewals:** Instead of creating new tokens, extend existing ones to maintain token string consistency
5. **Monitor Status:** Use `/api/token/info` to track usage before limits are reached
6. **Graceful Revocation:** Use `/api/token/disable` for immediate access removal
7. **Device Health:** Use `/api/health` to monitor token capacity usage and system resources

### Error Handling
1. **Retry Logic:** Implement exponential backoff for failures
2. **Validate Responses:** Always check `success` field
3. **Log Errors:** Keep track of API failures for debugging
4. **Handle TOKEN_NOT_FOUND:** Design graceful fallbacks when tokens are unavailable:
   - For info queries: Notify user token is invalid
   - For disable: Treat as success (already disabled)
   - For extend: Offer to create new token instead
5. **Network Errors:** Handle connection timeouts and network issues gracefully

### API Integration
1. **Check Before Extend:** Use `/api/token/info` to verify token exists before extending
2. **Batch Operations:** If managing many tokens, implement queuing to avoid overwhelming the device
3. **Cache API Key:** Load API key once at startup, not on every request
4. **Status Monitoring:** Poll `/api/token/info` periodically for active subscriptions
5. **Database Sync:** Store token-to-customer mappings in your database for subscription management

## Example Integration

### Vending/Payment System
```python
def sell_wifi_access(customer, hours, mb_limit):
    """Generate WiFi token after payment"""
    try:
        response = requests.post(
            'http://192.168.0.100/api/token',
            data={
                'api_key': os.getenv('ESP32_API_KEY'),
                'duration': hours * 60,
                'bandwidth_down': mb_limit,
                'bandwidth_up': mb_limit // 2
            },
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            if data['success']:
                token = data['token']
                # Print receipt or send via SMS/email
                print(f"Your WiFi Code: {token}")
                print(f"Valid for: {hours} hours")
                print(f"Data: {mb_limit}MB")
                return token
        
        raise Exception("Token generation failed")
        
    except Exception as e:
        print(f"Error: {e}")
        return None
```

### Subscription Management System
```python
def manage_subscription(customer_id, action):
    """Handle subscription renewals and cancellations"""
    api_key = os.getenv('ESP32_API_KEY')
    token = get_customer_token(customer_id)  # From your database
    
    if action == 'renew':
        # Extend existing token
        response = requests.post(
            'http://192.168.0.100/api/token/extend',
            data={'api_key': api_key, 'token': token}
        )
        
        if response.status_code == 404:
            # Token doesn't exist, create new one
            print(f"Token expired, creating new one for {customer_id}")
            response = requests.post(
                'http://192.168.0.100/api/token',
                data={
                    'api_key': api_key,
                    'duration': 10080,  # 7 days
                    'bandwidth_down': 10000  # 10GB
                }
            )
            if response.ok and response.json()['success']:
                new_token = response.json()['token']
                update_customer_token(customer_id, new_token)
                return new_token
        
        elif response.ok:
            print(f"Token {token} extended for {customer_id}")
            return token
            
    elif action == 'cancel':
        # Disable token immediately
        response = requests.post(
            'http://192.168.0.100/api/token/disable',
            data={'api_key': api_key, 'token': token}
        )
        
        if response.status_code in [200, 404]:  # Success or already disabled
            print(f"Subscription cancelled for {customer_id}")
            return True
    
    return False

def check_token_status(token):
    """Monitor token usage for billing/alerts"""
    response = requests.get(
        'http://192.168.0.100/api/token/info',
        params={
            'api_key': os.getenv('ESP32_API_KEY'),
            'token': token
        }
    )
    
    if response.status_code == 404:
        return {'status': 'not_found', 'message': 'Token has been removed or disabled'}
    
    if response.ok:
        data = response.json()
        
        # Check if approaching limits
        if data['status'] == 'active':
            usage_percent = (data['bandwidth_used_down_mb'] / data['bandwidth_down_mb'] * 100) if data['bandwidth_down_mb'] > 0 else 0
            time_percent = ((data['duration_minutes'] * 60 - data['remaining_seconds']) / (data['duration_minutes'] * 60) * 100)
            
            if usage_percent > 80 or time_percent > 80:
                return {
                    'status': 'warning',
                    'message': 'Approaching limits',
                    'data_used': usage_percent,
                    'time_used': time_percent
                }
        
        return {'status': data['status'], 'data': data}
    
    return {'status': 'error', 'message': 'API request failed'}
```

## Support & Issues
For technical issues or feature requests, contact your system administrator or refer to the project documentation.

## Version History
- **v3.0** (2025-12-10): Monitoring & Capacity Improvements
  - **NEW:** `GET /api/uptime` - System uptime monitoring (no auth required)
  - **NEW:** `GET /api/health` - Comprehensive health check endpoint
  - Increased token capacity from 50 to 230 tokens
  - Automatic token cleanup every 30 seconds (on SNTP sync)
  - HTTP response refactoring for code reuse and flash savings
  - Kubernetes/Prometheus integration examples
  - Enhanced monitoring and alerting documentation

- **v2.0** (2025-12-09): Enhanced Token Management
  - **NEW:** `POST /api/token/disable` - Revoke tokens instantly
  - **NEW:** `GET /api/token/info` - Query token status and usage statistics
  - **NEW:** `POST /api/token/extend` - Renew/top-up existing tokens
  - **NEW:** Static IP configuration for uplink network
  - Standardized error codes (TOKEN_NOT_FOUND)
  - Improved error handling and documentation
  - Added subscription management examples

- **v1.0** (2025-12-09): Initial release
  - Token generation API
  - Bandwidth limits support
  - Device limit enforcement
  - Session management
  - Admin password management
