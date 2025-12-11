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
| `bandwidth_down` | integer | **No** | Download limit in MB (0 or omitted = unlimited, **no negative values**) |
| `bandwidth_up` | integer | **No** | Upload limit in MB (0 or omitted = unlimited, **no negative values**) |

**Duration Validation:**
- Minimum: 30 minutes
- Maximum: 43,200 minutes (30 days = 43,200 minutes exactly)
- **Must be positive** - negative values return 400 error
- Range is inclusive: 30 ≤ duration ≤ 43200

**Bandwidth Limits (Optional):**
- Set to 0 or **omit entirely** for unlimited bandwidth
- **Must be non-negative** - negative values return 400 error with specific message
- Token expires when either time OR bandwidth limit is reached (whichever comes first)
- Bandwidth tracking is per-token across all devices using it

**Device Limit:**
- Each token supports maximum 2 simultaneous devices
- Devices are tracked by MAC address
- Device slots released when device disconnects

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
- Token storage limit reached (max 230 active tokens)
- Missing required parameters (api_key or duration)
- System time not synchronized yet (wait ~10 seconds after boot)

**Negative Values**

**Code:** `400 Bad Request`
```json
{
    "success": false,
    "error": "Duration cannot be negative"
}
```
OR
```json
{
    "success": false,
    "error": "Bandwidth cannot be negative"
}
```

These specific errors occur when:
- `duration` parameter contains a negative value (e.g., `-30`)
- `bandwidth_down` or `bandwidth_up` contains a negative value (e.g., `-100`)
- **Validation happens before any other processing** to prevent invalid data entry

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
Permanently disable and delete a token from the system. This operation:
- Immediately revokes token access (active sessions are terminated)
- Removes token from memory (active_tokens array)
- Erases token from NVS flash storage
- Decrements the active token count
- **Persists across device reboots** - token cannot be recovered

**Use Cases:**
- Revoking access for security reasons
- Canceling unused/expired tokens to free capacity
- Bulk cleanup of old tokens
- Subscription cancellation

**Important:** This is a permanent deletion. The token cannot be restored and will not reappear after device reboot.

#### Request

**Content-Type:** `application/x-www-form-urlencoded`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_key` | string | Yes | Your 32-character API key |
| `token` | string | Yes | The 8-character token to permanently delete |

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

**Verification:**
After successful deletion, you can verify the token is gone by:
1. Query `/api/token/info` - will return 404
2. Check `/api/health` - `active_tokens` count decremented
3. Reboot device - token remains deleted (persists in NVS)

**Internal Operations (logged to device console):**
```
I (143100) esp32-mesh-portal: Erased token C25DL85Y from NVS (erase=ESP_OK, commit=ESP_OK)
I (143100) esp32-mesh-portal: API: Token C25DL85Y disabled via API (count now: 89)
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
- The token doesn't exist in the system
- The token has already been disabled and deleted
- The token string was entered incorrectly (case-sensitive)

**Note:** If you receive 404, the token is guaranteed not to exist in the system. This is idempotent - calling disable on an already-disabled token returns 404, not an error.

**NVS Storage Errors (Rare)**

If the device encounters an NVS storage error during deletion, it will still be logged to the console:
```
E (xxxxx) esp32-mesh-portal: Failed to erase token XXXXXXXX from NVS: <error_name> (0x<code>)
E (xxxxx) esp32-mesh-portal: Failed to commit NVS after erasing token XXXXXXXX: <error_name> (0x<code>)
```

Common NVS errors:
- `ESP_ERR_NVS_NOT_FOUND` (0x1102) - Already deleted
- `ESP_ERR_NVS_INVALID_HANDLE` (0x1101) - Storage corruption

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

**Example 1: Unused Token**
```json
{
    "success": true,
    "token": "A3K9M7P2",
    "status": "unused",
    "created": 1702123456,
    "first_use": 0,
    "duration_minutes": 120,
    "expires_at": 1702130656,
    "remaining_seconds": 0,
    "bandwidth_down_mb": 500,
    "bandwidth_up_mb": 100,
    "bandwidth_used_down_mb": 0,
    "bandwidth_used_up_mb": 0,
    "usage_count": 0,
    "device_count": 0,
    "max_devices": 2,
    "client_macs": []
}
```

**Example 2: Active Token (Single Device)**
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
    "max_devices": 2,
    "client_macs": ["AA:BB:CC:DD:EE:FF"]
}
```

**Example 3: Active Token (Multiple Devices)**
```json
{
    "success": true,
    "token": "B7X2K9L4",
    "status": "active",
    "created": 1702123456,
    "first_use": 1702124000,
    "duration_minutes": 120,
    "expires_at": 1702131200,
    "remaining_seconds": 3600,
    "bandwidth_down_mb": 500,
    "bandwidth_up_mb": 100,
    "bandwidth_used_down_mb": 280,
    "bandwidth_used_up_mb": 45,
    "usage_count": 24,
    "device_count": 2,
    "max_devices": 2,
    "client_macs": ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]
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
| `client_macs` | array | MAC addresses of devices using token (empty array if unused) |

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
Extend/renew an existing token by resetting its timer and usage counters back to zero. This gives the token a complete "fresh start" as if it was just created, using the same duration and bandwidth limits as the original token.

**What It Does:**
- ✅ Resets `first_use` to current time → Duration countdown restarts from 0
- ✅ Resets `bandwidth_used_down` and `bandwidth_used_up` to 0 → Bandwidth allowance fully restored
- ✅ Resets `usage_count` to 0 → Usage counter cleared
- ✅ Persists changes to NVS → Survives device reboots
- ⚠️ **Does NOT change** `duration_minutes`, `bandwidth_down_mb`, or `bandwidth_up_mb` → Original limits preserved
- ⚠️ **Does NOT remove** device bindings → Same devices can continue using the token

**Use Cases:**
- **Subscription Renewal:** Customer pays for another period, extend their existing token
- **Top-Up Service:** Add more time/bandwidth without issuing a new token
- **Grace Period:** Reset token for customers who exceeded limits but want to continue
- **Customer Retention:** Offer free extension as promotional benefit

**Important:** The token keeps its original duration and bandwidth parameters from creation. You cannot change these values via extend - if different limits are needed, create a new token instead.

#### Request

**Content-Type:** `application/x-www-form-urlencoded`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_key` | string | Yes | Your 32-character API key |
| `token` | string | Yes | The 8-character token to extend |

**No Additional Parameters:**
- Cannot modify `duration_minutes` - uses original value
- Cannot modify `bandwidth_down_mb` - uses original value  
- Cannot modify `bandwidth_up_mb` - uses original value
- To change these values, create a new token with `/api/token/create`

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
    "new_duration_minutes": 120,
    "new_expires_at": 1702138400,
    "bandwidth_down_mb": 500,
    "bandwidth_up_mb": 100
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `message` | string | Confirmation message: "Token extended successfully" |
| `token` | string | The extended token (same as input) |
| `duration_minutes` | integer | **Original** duration from token creation (unchanged) |
| `new_duration_minutes` | integer | Duration for this extension period (always same as `duration_minutes`) |
| `new_expires_at` | integer | **New** expiration Unix timestamp (current time + duration_minutes) |
| `bandwidth_down_mb` | integer | Download limit in MB (unchanged from original, 0 = unlimited) |
| `bandwidth_up_mb` | integer | Upload limit in MB (unchanged from original, 0 = unlimited) |

**What Actually Changed:**
- `first_use` → Set to current timestamp (timer restarted)
- `bandwidth_used_down` → Reset to 0 (usage cleared)
- `bandwidth_used_up` → Reset to 0 (usage cleared)
- `usage_count` → Reset to 0 (login counter cleared)
- `new_expires_at` → Calculated as: current time + (duration_minutes × 60)

**What Stayed The Same:**
- `duration_minutes` → Kept from original token creation
- `bandwidth_down_mb` → Kept from original token creation
- `bandwidth_up_mb` → Kept from original token creation
- Device bindings → Previous devices can still use the token

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

**Example - Extend with Fallback to Create:**
```python
def renew_or_create_token(api_key, token, duration=120):
    """Try to extend existing token, create new one if not found"""
    # Try extending first
    response = requests.post(
        'http://192.168.0.100/api/token/extend',
        data={'api_key': api_key, 'token': token}
    )
    
    if response.status_code == 404:
        # Token doesn't exist - create a new one
        return requests.post(
            'http://192.168.0.100/api/token/create',
            data={
                'api_key': api_key,
                'duration': duration,
                'bandwidth_down': 500,  # Set new limits
                'bandwidth_up': 100
            }
        ).json()
    
    return response.json()
```

**Other Errors:** Same as `/api/token/create` endpoint (401, 403, 400)

#### Internal State Changes

When a token is extended, the following internal state changes occur:

**Before Extend (Example Token):**
```
Token: A3K9M7P2
first_use: 1702050000 (Dec 8, 2024 12:00:00)
duration_minutes: 120
bandwidth_used_down: 450 MB (out of 500 MB limit)
bandwidth_used_up: 80 MB (out of 100 MB limit)
usage_count: 15
expires_at: 1702057200 (Dec 8, 2024 14:00:00) ← EXPIRED
```

**After Extend:**
```
Token: A3K9M7P2 (same token)
first_use: 1702138400 (Dec 9, 2024 12:00:00) ← RESET to now
duration_minutes: 120 (unchanged)
bandwidth_used_down: 0 ← RESET
bandwidth_used_up: 0 ← RESET
usage_count: 0 ← RESET
expires_at: 1702145600 (Dec 9, 2024 14:00:00) ← NEW expiration
```

**Persisted to NVS:** All changes are immediately saved to non-volatile storage and survive device reboots.

**Device Bindings:** If the token was previously used by devices with MACs `AA:BB:CC:DD:EE:FF` and `11:22:33:44:55:66`, these same devices can continue using the token without re-authenticating.

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

### GET /api/tokens/list
Get a complete list of all active tokens in the system with their full metadata. This endpoint is essential for bulk token management, monitoring dashboards, and system auditing.

#### Request

**Method:** GET

**Authentication:** Required (API key)

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_key` | string | Yes | Your 32-character API key |

#### Example Requests

**cURL:**
```bash
curl -X GET "http://192.168.0.100/api/tokens/list?api_key=abcd1234efgh5678ijkl9012mnop3456"
```

**Python:**
```python
import requests

params = {
    "api_key": "abcd1234efgh5678ijkl9012mnop3456"
}

response = requests.get('http://192.168.0.100/api/tokens/list', params=params)
data = response.json()

print(f"Total tokens: {data['count']}")
for token in data['tokens']:
    print(f"Token: {token['token']}, Status: {token['status']}, "
          f"Duration: {token['duration_minutes']} min")
```

**JavaScript:**
```javascript
const axios = require('axios');

const params = {
    api_key: 'abcd1234efgh5678ijkl9012mnop3456'
};

axios.get('http://192.168.0.100/api/tokens/list', { params })
    .then(response => {
        const data = response.data;
        console.log(`Total tokens: ${data.count}`);
        data.tokens.forEach(token => {
            console.log(`${token.token}: ${token.status}, ${token.duration_minutes}min`);
        });
    })
    .catch(error => console.error(error));
```

#### Success Response

**Code:** `200 OK`

```json
{
    "success": true,
    "count": 3,
    "tokens": [
        {
            "token": "A3K9M7P2",
            "status": "active",
            "duration_minutes": 120,
            "first_use": 1702345678,
            "expires_at": 1702352878,
            "remaining_seconds": 3600,
            "bandwidth_down_mb": 500,
            "bandwidth_up_mb": 100,
            "bandwidth_used_down": 245,
            "bandwidth_used_up": 38,
            "usage_count": 2,
            "device_count": 2,
            "client_macs": ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]
        },
        {
            "token": "TT5N25GG",
            "status": "unused",
            "duration_minutes": 30,
            "first_use": 0,
            "expires_at": 1702349278,
            "remaining_seconds": 1800,
            "bandwidth_down_mb": 0,
            "bandwidth_up_mb": 0,
            "bandwidth_used_down": 0,
            "bandwidth_used_up": 0,
            "usage_count": 0,
            "device_count": 0,
            "client_macs": []
        },
        {
            "token": "X8R2D4F1",
            "status": "expired",
            "duration_minutes": 60,
            "first_use": 1702340000,
            "expires_at": 1702343600,
            "remaining_seconds": 0,
            "bandwidth_down_mb": 1000,
            "bandwidth_up_mb": 250,
            "bandwidth_used_down": 890,
            "bandwidth_used_up": 220,
            "usage_count": 5,
            "device_count": 1,
            "client_macs": ["77:88:99:AA:BB:CC"]
        }
    ]
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `success` | boolean | Always true for successful requests |
| `count` | integer | Total number of active tokens in the system |
| `tokens` | array | Array of token objects with detailed metadata |

**Token Object Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `token` | string | 8-character token code |
| `status` | string | Token status: "unused" (never used), "active" (in use), "expired" (time/bandwidth exceeded) |
| `duration_minutes` | integer | Token duration from creation (30-43200 minutes) |
| `first_use` | integer | Unix timestamp of first use (0 = never used) |
| `expires_at` | integer | Unix timestamp when token expires |
| `remaining_seconds` | integer | Seconds until expiration (0 if expired) |
| `bandwidth_down_mb` | integer | Download limit in MB (0 = unlimited) |
| `bandwidth_up_mb` | integer | Upload limit in MB (0 = unlimited) |
| `bandwidth_used_down` | integer | Downloaded data in MB |
| `bandwidth_used_up` | integer | Uploaded data in MB |
| `usage_count` | integer | Number of times token was authenticated |
| `device_count` | integer | Number of devices currently using this token (0-2) |
| `client_macs` | array | MAC addresses of devices using token (empty array if unused, max 2 devices) |

**Status Values:**
- `"unused"` - Token created but never used (first_use = 0)
- `"active"` - Token currently in use and not expired (remaining_seconds > 0)
- `"expired"` - Token expired due to time or bandwidth limit (remaining_seconds = 0)

#### Use Cases

**1. Bulk Token Cleanup**
```bash
#!/bin/bash
API_KEY="your_api_key_here"
ESP32_IP="192.168.0.100"

# Get all expired tokens and disable them
tokens=$(curl -s "http://$ESP32_IP/api/tokens/list?api_key=$API_KEY" | \
  python3 -c "import sys, json; data=json.load(sys.stdin); \
  print(' '.join([t['token'] for t in data['tokens'] if t['status']=='expired']))")

for token in $tokens; do
  curl -s -X POST "http://$ESP32_IP/api/token/disable" \
    -d "api_key=$API_KEY&token=$token"
  echo "Cleaned up expired token: $token"
done
```

**2. Monitoring Dashboard**
```python
def get_token_statistics(api_key, esp32_ip):
    """Get aggregated token statistics for monitoring"""
    response = requests.get(
        f'http://{esp32_ip}/api/tokens/list',
        params={'api_key': api_key}
    )
    data = response.json()
    
    stats = {
        'total': data['count'],
        'unused': sum(1 for t in data['tokens'] if t['status'] == 'unused'),
        'active': sum(1 for t in data['tokens'] if t['status'] == 'active'),
        'expired': sum(1 for t in data['tokens'] if t['status'] == 'expired'),
        'total_bandwidth_used': sum(
            t['bandwidth_used_down'] + t['bandwidth_used_up'] 
            for t in data['tokens']
        )
    }
    
    return stats
```

**3. Token Usage Analytics**
```python
def analyze_token_usage(api_key, esp32_ip):
    """Analyze token usage patterns"""
    response = requests.get(
        f'http://{esp32_ip}/api/tokens/list',
        params={'api_key': api_key}
    )
    data = response.json()
    
    # Find most used tokens
    active_tokens = [t for t in data['tokens'] if t['usage_count'] > 0]
    active_tokens.sort(key=lambda t: t['usage_count'], reverse=True)
    
    print(f"Top 5 most used tokens:")
    for token in active_tokens[:5]:
        print(f"  {token['token']}: {token['usage_count']} logins, "
              f"{token['bandwidth_used_down']}MB down")
```

**4. Find Tokens by MAC Address**
```python
def find_tokens_by_mac(api_key, esp32_ip, target_mac):
    """Find all tokens associated with a specific device MAC address"""
    response = requests.get(
        f'http://{esp32_ip}/api/tokens/list',
        params={'api_key': api_key}
    )
    data = response.json()
    
    # Find tokens containing the target MAC
    matching_tokens = [
        token for token in data['tokens']
        if target_mac.upper() in [mac.upper() for mac in token['client_macs']]
    ]
    
    if matching_tokens:
        print(f"Found {len(matching_tokens)} token(s) for MAC {target_mac}:")
        for token in matching_tokens:
            print(f"  Token: {token['token']}")
            print(f"    Status: {token['status']}")
            print(f"    Devices: {token['device_count']}")
            print(f"    MACs: {', '.join(token['client_macs'])}")
            print(f"    Bandwidth used: {token['bandwidth_used_down']}MB down, "
                  f"{token['bandwidth_used_up']}MB up")
    else:
        print(f"No tokens found for MAC {target_mac}")
    
    return matching_tokens

# Example usage
find_tokens_by_mac('your_api_key', '192.168.0.100', 'AA:BB:CC:DD:EE:FF')
```

**5. Device Tracking Report**
```python
def generate_device_report(api_key, esp32_ip):
    """Generate report of all devices using tokens"""
    response = requests.get(
        f'http://{esp32_ip}/api/tokens/list',
        params={'api_key': api_key}
    )
    data = response.json()
    
    # Collect all unique MACs
    devices = {}
    for token in data['tokens']:
        for mac in token['client_macs']:
            if mac not in devices:
                devices[mac] = []
            devices[mac].append({
                'token': token['token'],
                'status': token['status'],
                'bandwidth_down': token['bandwidth_used_down'],
                'bandwidth_up': token['bandwidth_used_up']
            })
    
    print(f"Device Report - {len(devices)} unique devices:")
    for mac, tokens in devices.items():
        total_bandwidth = sum(t['bandwidth_down'] + t['bandwidth_up'] for t in tokens)
        print(f"\n{mac}:")
        print(f"  Tokens used: {len(tokens)}")
        print(f"  Total bandwidth: {total_bandwidth}MB")
        for t in tokens:
            print(f"    - {t['token']} ({t['status']}): "
                  f"{t['bandwidth_down']}MB down, {t['bandwidth_up']}MB up")
```

**6. Clear All Tokens**
```bash
# Disable all tokens in the system
tokens=$(curl -s "http://192.168.0.100/api/tokens/list?api_key=$API_KEY" | \
  python3 -c "import sys, json; data=json.load(sys.stdin); \
  print(' '.join([t['token'] for t in data['tokens']]))")

for token in $tokens; do
  curl -s -X POST "http://192.168.0.100/api/token/disable" \
    -d "api_key=$API_KEY&token=$token"
  sleep 0.15  # Rate limiting
done
```

#### Error Responses

**Missing API Key**

**Code:** `400 Bad Request`
```json
{
    "success": false,
    "error": "Missing required parameter: api_key"
}
```

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

**Memory Allocation Failed**

**Code:** `500 Internal Server Error`
```json
{
    "success": false,
    "error": "Memory allocation failed"
}
```

This error is rare and indicates the device is under extreme memory pressure. If this occurs:
1. Reduce the number of active tokens
2. Reboot the device to clear memory
3. Consider implementing periodic token cleanup

#### Performance Notes

- **Response Size:** Approximately 200-250 bytes per token
- **Maximum Response:** ~58KB for 230 tokens (8KB buffer, may truncate if list is very large)
- **Response Time:** Typically 50-200ms depending on token count
- **Rate Limiting:** Recommend 100ms minimum between requests to avoid overwhelming device

---

## MAC Address Filtering

The ESP32 Portal includes MAC address filtering capabilities to manage device access:
- **Blacklist:** Block specific devices from accessing the network
- **Whitelist:** Grant VIP bypass access (no token needed after first redemption)

All MAC filtering operations enforce **mutual exclusivity** - adding a MAC to one list automatically removes it from the other.

### POST /api/mac/blacklist
Add all MAC addresses associated with a token to the blacklist. Blacklisted devices will see an "Access Denied" page and cannot access the network.

#### Request

**Content-Type:** `application/x-www-form-urlencoded`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_key` | string | Yes | Your 32-character API key |
| `token` | string | Yes | 8-character token to extract MACs from |
| `reason` | string | No | Reason for blocking (max 31 chars, default: "Blocked by admin") |

#### Example Requests

**cURL:**
```bash
curl -X POST http://192.168.0.100/api/mac/blacklist \
  -d "api_key=abcd1234efgh5678ijkl9012mnop3456" \
  -d "token=A3K9M7P2" \
  -d "reason=Policy violation"
```

**Python:**
```python
import requests

data = {
    "api_key": "abcd1234efgh5678ijkl9012mnop3456",
    "token": "A3K9M7P2",
    "reason": "Policy violation"
}

response = requests.post('http://192.168.0.100/api/mac/blacklist', data=data)
result = response.json()

if result['success']:
    print(f"Blacklisted {result['count']} MAC address(es)")
```

#### Success Response

**Code:** `200 OK`

```json
{
    "success": true,
    "message": "Added 2 MAC(s) to blacklist",
    "count": 2
}
```

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

**No MACs to Blacklist**

**Code:** `400 Bad Request`
```json
{
    "success": false,
    "error": "Token has no client MACs to blacklist"
}
```

**Other Errors:** Same as other API endpoints (401, 403, 400 for missing parameters)

---

### POST /api/mac/whitelist
Add all MAC addresses associated with a token to the whitelist. Whitelisted devices receive VIP bypass access - they can use the internet without needing to redeem a token after their first use.

#### Request

**Content-Type:** `application/x-www-form-urlencoded`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_key` | string | Yes | Your 32-character API key |
| `token` | string | Yes | 8-character token to extract MACs from |
| `note` | string | No | Note about the whitelist entry (max 31 chars, default: "VIP access") |

#### Example Requests

**cURL:**
```bash
curl -X POST http://192.168.0.100/api/mac/whitelist \
  -d "api_key=abcd1234efgh5678ijkl9012mnop3456" \
  -d "token=A3K9M7P2" \
  -d "note=Premium customer"
```

**Python:**
```python
import requests

data = {
    "api_key": "abcd1234efgh5678ijkl9012mnop3456",
    "token": "A3K9M7P2",
    "note": "Premium customer"
}

response = requests.post('http://192.168.0.100/api/mac/whitelist', data=data)
result = response.json()

if result['success']:
    print(f"Whitelisted {result['count']} MAC address(es) for VIP bypass")
```

#### Success Response

**Code:** `200 OK`

```json
{
    "success": true,
    "message": "Added 2 MAC(s) to whitelist (VIP bypass)",
    "count": 2
}
```

#### Error Responses

Same as `/api/mac/blacklist` endpoint.

---

### GET /api/mac/list
Retrieve all blacklist and whitelist entries with their associated metadata.

#### Request

**Method:** GET

**Authentication:** Required (API key)

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_key` | string | Yes | Your 32-character API key |

#### Example Requests

**cURL:**
```bash
curl -X GET "http://192.168.0.100/api/mac/list?api_key=abcd1234efgh5678ijkl9012mnop3456"
```

**Python:**
```python
import requests

params = {"api_key": "abcd1234efgh5678ijkl9012mnop3456"}
response = requests.get('http://192.168.0.100/api/mac/list', params=params)
data = response.json()

print(f"Blacklist: {data['blacklist_count']} entries")
for entry in data['blacklist']:
    print(f"  {entry['mac']}: {entry['reason']}")

print(f"\nWhitelist: {data['whitelist_count']} entries")
for entry in data['whitelist']:
    print(f"  {entry['mac']}: {entry['note']}")
```

#### Success Response

**Code:** `200 OK`

```json
{
    "success": true,
    "blacklist": [
        {
            "mac": "AA:BB:CC:DD:EE:FF",
            "token": "A3K9M7P2",
            "reason": "Policy violation",
            "added": 1702234567
        }
    ],
    "whitelist": [
        {
            "mac": "11:22:33:44:55:66",
            "token": "B7X2K9F1",
            "note": "Premium customer",
            "added": 1702234890
        }
    ],
    "blacklist_count": 1,
    "whitelist_count": 1
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `blacklist` | array | Array of blacklist entries |
| `whitelist` | array | Array of whitelist entries |
| `blacklist_count` | integer | Total number of blacklisted MACs |
| `whitelist_count` | integer | Total number of whitelisted MACs |
| `mac` | string | MAC address (format: XX:XX:XX:XX:XX:XX) |
| `token` | string | Token that was used to add this MAC |
| `reason` | string | Blacklist reason |
| `note` | string | Whitelist note |
| `added` | integer | Unix timestamp when entry was added |

---

### POST /api/mac/remove
Remove a MAC address from the blacklist, whitelist, or both.

#### Request

**Content-Type:** `application/x-www-form-urlencoded`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_key` | string | Yes | Your 32-character API key |
| `mac` | string | Yes | MAC address to remove (format: XX:XX:XX:XX:XX:XX) |
| `list` | string | No | Which list to remove from: "blacklist", "whitelist", or "both" (default: "both") |

#### Example Requests

**cURL - Remove from both lists:**
```bash
curl -X POST http://192.168.0.100/api/mac/remove \
  -d "api_key=abcd1234efgh5678ijkl9012mnop3456" \
  -d "mac=AA:BB:CC:DD:EE:FF"
```

**cURL - Remove from blacklist only:**
```bash
curl -X POST http://192.168.0.100/api/mac/remove \
  -d "api_key=abcd1234efgh5678ijkl9012mnop3456" \
  -d "mac=AA:BB:CC:DD:EE:FF" \
  -d "list=blacklist"
```

**Python:**
```python
import requests

# Remove from both lists
data = {
    "api_key": "abcd1234efgh5678ijkl9012mnop3456",
    "mac": "AA:BB:CC:DD:EE:FF",
    "list": "both"
}

response = requests.post('http://192.168.0.100/api/mac/remove', data=data)
result = response.json()

if result['success']:
    print(f"MAC removed from {data['list']}")
```

#### Success Response

**Code:** `200 OK`

```json
{
    "success": true,
    "message": "MAC removed from both"
}
```

#### Error Responses

**MAC Not Found**

**Code:** `404 Not Found`
```json
{
    "success": false,
    "error": "MAC not found in specified list(s)"
}
```

**Invalid MAC Format**

**Code:** `400 Bad Request`
```json
{
    "success": false,
    "error": "Invalid MAC address format (use XX:XX:XX:XX:XX:XX)"
}
```

---

### POST /api/mac/clear
Clear all entries from the blacklist, whitelist, or both. Use with caution - this operation cannot be undone.

#### Request

**Content-Type:** `application/x-www-form-urlencoded`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `api_key` | string | Yes | Your 32-character API key |
| `list` | string | No | Which list to clear: "blacklist", "whitelist", or "both" (default: "both") |

#### Example Requests

**cURL - Clear both lists:**
```bash
curl -X POST http://192.168.0.100/api/mac/clear \
  -d "api_key=abcd1234efgh5678ijkl9012mnop3456"
```

**cURL - Clear blacklist only:**
```bash
curl -X POST http://192.168.0.100/api/mac/clear \
  -d "api_key=abcd1234efgh5678ijkl9012mnop3456" \
  -d "list=blacklist"
```

**Python:**
```python
import requests

data = {
    "api_key": "abcd1234efgh5678ijkl9012mnop3456",
    "list": "blacklist"
}

response = requests.post('http://192.168.0.100/api/mac/clear', data=data)
result = response.json()

if result['success']:
    print(f"Cleared {result['entries_removed']} entries from {data['list']}")
```

#### Success Response

**Code:** `200 OK`

```json
{
    "success": true,
    "message": "Cleared blacklist",
    "entries_removed": 5
}
```

---

### MAC Filtering Use Cases

**1. Block Abusive Users**
```python
# Block all devices used by a specific token
def block_token_devices(api_key, esp32_ip, token, reason):
    response = requests.post(
        f'http://{esp32_ip}/api/mac/blacklist',
        data={
            'api_key': api_key,
            'token': token,
            'reason': reason
        }
    )
    return response.json()

# Example: Block excessive bandwidth user
block_token_devices(
    'your_api_key',
    '192.168.0.100',
    'A3K9M7P2',
    'Excessive bandwidth usage'
)
```

**2. VIP Customer Management**
```python
# Grant VIP access to premium customers
def grant_vip_access(api_key, esp32_ip, token, note):
    response = requests.post(
        f'http://{esp32_ip}/api/mac/whitelist',
        data={
            'api_key': api_key,
            'token': token,
            'note': note
        }
    )
    return response.json()

# Example: Add premium customer
grant_vip_access(
    'your_api_key',
    '192.168.0.100',
    'B7X2K9F1',
    'Premium subscription'
)
```

**3. Audit MAC Filters**
```python
# Generate report of all filtered MACs
def audit_mac_filters(api_key, esp32_ip):
    response = requests.get(
        f'http://{esp32_ip}/api/mac/list',
        params={'api_key': api_key}
    )
    data = response.json()
    
    print(f"Blacklisted Devices: {data['blacklist_count']}")
    for entry in data['blacklist']:
        print(f"  {entry['mac']}: {entry['reason']} (added: {entry['added']})")
    
    print(f"\nVIP Devices: {data['whitelist_count']}")
    for entry in data['whitelist']:
        print(f"  {entry['mac']}: {entry['note']} (added: {entry['added']})")

audit_mac_filters('your_api_key', '192.168.0.100')
```

**4. Temporary Block with Auto-Unblock**
```python
import time

# Block device temporarily
def temporary_block(api_key, esp32_ip, mac, duration_minutes, reason):
    # Add to blacklist
    requests.post(
        f'http://{esp32_ip}/api/mac/blacklist',
        data={'api_key': api_key, 'token': 'TEMP0001', 'reason': reason}
    )
    
    print(f"Blocked {mac} for {duration_minutes} minutes")
    
    # Wait
    time.sleep(duration_minutes * 60)
    
    # Remove from blacklist
    requests.post(
        f'http://{esp32_ip}/api/mac/remove',
        data={'api_key': api_key, 'mac': mac, 'list': 'blacklist'}
    )
    
    print(f"Unblocked {mac}")

# Example: 30-minute timeout
temporary_block(
    'your_api_key',
    '192.168.0.100',
    'AA:BB:CC:DD:EE:FF',
    30,
    'Rate limit exceeded'
)
```

---

## Error Code Reference

All API endpoints may return the following standard error codes:

| Error Code | HTTP Status | Description | Resolution |
|------------|-------------|-------------|------------|
| `TOKEN_NOT_FOUND` | 404 | Token doesn't exist or has been disabled | Check token spelling, verify it wasn't disabled, or create a new token |
| `ENDPOINT_NOT_FOUND` | 404 | Invalid API endpoint | Verify URL path matches documented endpoints exactly |
| N/A (Invalid API key) | 401 | API key is incorrect | Verify API key from admin dashboard, regenerate if needed |
| N/A (Forbidden) | 403 | Request from guest network | Make API calls from uplink network only |
| N/A (Bad Request) | 400 | Missing or invalid parameters | Check required parameters and value formats |
| N/A (Duration negative) | 400 | Duration parameter is negative | Use positive values: 30 ≤ duration ≤ 43200 |
| N/A (Bandwidth negative) | 400 | Bandwidth parameter is negative | Use positive values or omit parameter for unlimited |

### Handling ENDPOINT_NOT_FOUND

All invalid API endpoints return a `404 Not Found` response with an `ENDPOINT_NOT_FOUND` error:

**Request Example:**
```bash
curl -X POST http://192.168.0.100/api/invalid/path \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "api_key=your_api_key_here"
```

**Response:**
```json
{
    "success": false,
    "error": "ENDPOINT_NOT_FOUND"
}
```

**Common Mistakes:**
- Typos in endpoint path (e.g., `/api/token/crete` instead of `/api/token/create`)
- Using GET instead of POST for API endpoints
- Accessing endpoints that don't exist (e.g., `/api/token/list`)

**Valid API Endpoints:**
- `POST /api/token` - Create new token
- `POST /api/token/extend` - Reset/extend token
- `GET /api/token/info` - Query token information
- `POST /api/token/disable` - Disable token
- `GET /api/tokens/list` - List all tokens
- `POST /api/mac/blacklist` - Block devices
- `POST /api/mac/whitelist` - Grant VIP access
- `GET /api/mac/list` - List MAC filters
- `POST /api/mac/remove` - Remove MAC from filter
- `POST /api/mac/clear` - Clear MAC filters
- `GET /api/uptime` - Device uptime
- `GET /api/health` - System health metrics

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
- **v3.1** (2025-12-10): Bulk Token Management & Analytics
  - **NEW:** `GET /api/tokens/list` - List all active tokens with full metadata
  - Bulk token operations support (disable all, cleanup expired)
  - Token usage analytics and monitoring dashboard integration
  - System auditing and reporting capabilities
  - Comprehensive integration test suite (102 tests, 81% pass rate)

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
