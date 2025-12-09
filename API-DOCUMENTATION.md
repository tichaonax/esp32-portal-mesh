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
- Token storage limit reached (max 50 tokens)
- Missing required parameters

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
2. **Clean Up:** Expired tokens are automatically removed on device reboot
3. **Storage Limit:** Max 50 active tokens (create cleanup routines if needed)

### Error Handling
1. **Retry Logic:** Implement exponential backoff for failures
2. **Validate Responses:** Always check `success` field
3. **Log Errors:** Keep track of API failures for debugging

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

## Support & Issues
For technical issues or feature requests, contact your system administrator or refer to the project documentation.

## Version History
- **v1.0** (2025-12-09): Initial release
  - Token generation API
  - Bandwidth limits support
  - Device limit enforcement
  - Session management
  - Admin password management
