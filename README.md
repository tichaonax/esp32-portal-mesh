# ESP32 Captive Portal with Mesh Network

A comprehensive ESP32-based captive portal system with token authentication, NAT routing, and ESP-MESH networking capabilities.

## Features

### Phase 1: Basic Captive Portal (✅ Complete)
- **Token Authentication System**
  - 8-character alphanumeric tokens (excludes confusing characters: I, O, 0, 1)
  - NVS storage with 24-hour expiration
  - MAC address binding to prevent token sharing
  - Usage counting and expiration tracking
  - Tokens persist across reboots

- **Network Configuration**
  - WiFi AP: "ESP32-Guest-Portal" (open network)
  - IP Address: 192.168.4.1
  - Simultaneous AP/STA mode (APSTA)
  - Automatic connection to upstream router

- **NAT & Internet Routing**
  - lwIP NAPT enabled on AP interface
  - Routes authenticated client traffic through STA uplink
  - Full internet access for authenticated clients

- **DNS Forwarding**
  - Forwards authenticated client queries to Google DNS (8.8.8.8)
  - Captive portal redirect for unauthenticated clients

- **Web Interface**
  - Responsive HTML login page
  - Token validation with real-time feedback
  - Success/error messages with proper styling

### Phase 2: Token Administration Module (✅ Complete)
- **Modern Admin Dashboard** (`/admin`)
  - Beautiful responsive UI with gradient design
  - Password-protected interface (default: `admin123`)
  - Session management with auto-logout (5 minutes)
  - UTF-8 emoji support
  - Real-time WiFi status updates

- **Enhanced Token System**
  - Duration-based tokens (30 minutes to 30 days)
  - First-use activation (timer starts on first validation)
  - Bandwidth limits (separate download/upload in MB)
  - Multi-device support (max 2 devices per token)
  - Smart expiration (time OR bandwidth exhausted)

- **Token API for Third-Party Integration**
  - POST `/api/token` endpoint with duration and bandwidth parameters
  - API key authentication (32-character secure key)
  - Uplink IP restriction for security
  - Comprehensive documentation with cURL, Python, JavaScript examples

- **Admin Features**
  - API key management (display, regenerate)
  - Quick token generation (30min-12h dropdown)
  - WiFi configuration panel with live status
  - Admin password management
  - Logout functionality

- **Security Features**
  - API key validation for token generation
  - Session timeout tracking
  - IP-based access control (API only from uplink)
  - NVS storage for sensitive data
  - Password change validation

### Phase 3: ESP-MESH Integration (🚧 Starting)
- **Root Node Configuration**
  - ESP-MESH initialization
  - Root node as internet gateway
  - Mesh ID and password configuration
  - Topology management

- **Child Node Support**
  - Automatic parent selection
  - Self-healing mesh network
  - Mesh event handling
  - Multi-hop routing

### Future Enhancements (📋 Planned)
- **Bandwidth Tracking Implementation**
  - Real-time per-token bandwidth monitoring
  - Hook into lwIP for traffic counting per MAC address
  - Enforce bandwidth limits with automatic expiration

- **Bandwidth Limiting (QoS)**
  - Per-client traffic rate limiting
  - QoS implementation using lwIP
  - Configurable speed limits

- **Advanced Token Management**
  - View active tokens and usage statistics in admin panel
  - Token revocation capability
  - Bulk token generation
  - Token usage analytics

## Hardware Requirements

- ESP32 development board (tested on ESP32-D0WD-V3)
- USB cable for programming
- Access to a 2.4GHz WiFi router

## Software Requirements

- ESP-IDF v5.3
- Python 3.13+ (for ESP-IDF toolchain)

## Configuration

### Default Settings
```c
// Network Configuration
AP SSID: "ESP32-Guest-Portal"
AP IP: 192.168.4.1
Admin Password: "admin123"

// Token Configuration
Token Length: 8 characters
Token Expiration: 24 hours
Max Tokens: 50

// WiFi Configuration
Max Retry Attempts: 5
Channel: 4
Max AP Connections: 4
```

### Admin Panel Access
1. Connect to "ESP32-Guest-Portal" WiFi
2. Navigate to `http://192.168.4.1/admin`
3. Enter admin password (default: `admin123`)
4. Configure WiFi uplink credentials
5. View API key for third-party integration

### Token API Usage
For third-party applications to generate tokens:

```bash
# Example: Create 2-hour token with 500MB download/100MB upload limits
curl -X POST http://<UPLINK_IP>/api/token \
  -d "api_key=<YOUR_API_KEY>" \
  -d "duration=120" \
  -d "bandwidth_down=500" \
  -d "bandwidth_up=100"
```

See `API-DOCUMENTATION.md` for complete API reference with Python and JavaScript examples.

## Building and Flashing

```bash
# Setup ESP-IDF environment
source ~/esp-idf/export.sh

# Build the project
cd /path/to/esp32-portal-mesh
idf.py build

# Flash to ESP32
idf.py -p /dev/cu.usbserial-0001 flash

# Monitor serial output
idf.py -p /dev/cu.usbserial-0001 monitor
```

## Usage

### For Administrators
1. Flash firmware to ESP32
2. Connect to admin panel (`http://192.168.4.1/admin`)
3. Configure WiFi uplink to your router
4. Copy API key for third-party integration
5. Generate tokens via admin UI or API
6. Distribute tokens to users

### For Third-Party Applications
1. Obtain API key from admin dashboard
2. Use Token API endpoint to generate tokens programmatically
3. See `API-DOCUMENTATION.md` for detailed integration guide

### For Users
1. Connect to "ESP32-Guest-Portal" WiFi
2. Browser automatically opens captive portal
3. Enter provided 8-character token
4. Enjoy internet access with configured duration/bandwidth limits

## Network Architecture

```
Internet
   ↓
Router (2.4GHz WiFi)
   ↓
ESP32 (STA Interface) ← WiFi Connection
   ↓
ESP32 (AP Interface: 192.168.4.1) ← NAT Enabled
   ↓
Guest Devices (Token Authentication Required)
```

## Token System Flow

1. **Token Generation**: 
   - Admin creates tokens via dashboard (quick 30min-12h)
   - OR third-party apps use Token API with custom duration/bandwidth
2. **Client Connection**: User connects to ESP32 AP
3. **Captive Portal**: Browser redirected to login page
4. **Token Validation**: Token checked against NVS
5. **First Use Activation**: Timer starts on first validation
6. **MAC Binding**: Token bound to client MAC (supports up to 2 devices)
7. **Authentication**: Client added to authenticated list
8. **Internet Access**: NAT routes traffic through STA uplink
9. **Smart Expiration**: Token expires when duration OR bandwidth limit reached

## Troubleshooting

### WiFi Connection Issues
- Check disconnect reason codes in logs
- Reason 15: Authentication failed (wrong password)
- Reason 205: Association rejected
- Verify router is on 2.4GHz (ESP32 doesn't support 5GHz)

### Token Issues
- Tokens expire based on configured duration (30min - 30 days)
- Each token supports up to 2 MAC addresses
- Tokens activate on first use (not creation time)
- Check NVS storage if tokens aren't persisting
- Bandwidth limits are enforced (structure ready, tracking pending implementation)

### Admin Panel Issues
- Ensure connected to ESP32 AP
- Use IP address (192.168.4.1), not domain name
- Clear browser cache if page doesn't update

## Security Considerations

⚠️ **Important**: This is designed for controlled guest WiFi environments.

**Implemented Security:**
- Admin password protection with session management
- API key authentication (32-character random key)
- IP-based access control (API only from uplink network)
- Session timeout (5 minutes of inactivity)
- NVS storage for sensitive data
- Token-based guest authentication

**Production Recommendations:**
- Change default admin password immediately
- Regularly regenerate API keys
- Consider implementing HTTPS for admin panel
- Monitor API usage logs
- Keep API key confidential
- Use strong WiFi uplink passwords

**Known Limitations:**
- Open WiFi AP (no WPA encryption on guest network)
- Basic token system (alphanumeric strings)
- No built-in brute force protection
- Bandwidth tracking not yet implemented

## Project Structure

```
esp32-portal-mesh/
├── main/
│   ├── main.c              # Main application code
│   └── CMakeLists.txt
├── CMakeLists.txt
├── sdkconfig               # ESP-IDF configuration
├── API-DOCUMENTATION.md    # Complete Token API reference
├── .gitignore
└── README.md
```

## License

This project is provided as-is for educational and development purposes.

## Credits

Built using ESP-IDF v5.3 and the ESP32 platform.

---

**Current Status**: Phase 2 complete ✅ - Token Administration Module with modern admin dashboard, Token API for third-party integration, enhanced token system with duration/bandwidth/multi-device support, and comprehensive security features. Phase 3 (ESP-MESH) starting on `feature/mesh-networking` branch.
