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

### Phase 2: Admin Configuration (✅ Complete)
- **Admin Panel** (`/admin`)
  - Password-protected admin interface (default: `admin123`)
  - WiFi uplink configuration (SSID/Password)
  - Real-time connection status display
  - Credentials saved to NVS for persistence
  - Live connection status with RSSI information

- **WiFi Diagnostics**
  - Detailed connection failure logging
  - Disconnect reason codes with explanations
  - Authentication failure detection
  - Retry mechanism with configurable attempts

### Phase 3: ESP-MESH Integration (🚧 In Progress)
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
- **Bandwidth Limiting**
  - Per-client traffic rate limiting
  - QoS implementation using lwIP
  - Configurable speed limits

- **Token Management Interface**
  - Admin endpoints to generate tokens
  - View active tokens and usage statistics
  - Token revocation capability
  - Configurable expiration settings

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
5. Click "Update Configuration"

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
2. Connect to admin panel (http://192.168.4.1/admin)
3. Configure WiFi uplink to your router
4. Generate and distribute tokens to users

### For Users
1. Connect to "ESP32-Guest-Portal" WiFi
2. Browser automatically opens captive portal
3. Enter provided 8-character token
4. Enjoy internet access for 24 hours

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

1. **Token Generation**: Admin creates tokens in NVS
2. **Client Connection**: User connects to ESP32 AP
3. **Captive Portal**: Browser redirected to login page
4. **Token Validation**: Token checked against NVS
5. **MAC Binding**: Token bound to client MAC address
6. **Authentication**: Client added to authenticated list
7. **Internet Access**: NAT routes traffic through STA uplink

## Troubleshooting

### WiFi Connection Issues
- Check disconnect reason codes in logs
- Reason 15: Authentication failed (wrong password)
- Reason 205: Association rejected
- Verify router is on 2.4GHz (ESP32 doesn't support 5GHz)

### Token Issues
- Tokens expire after 24 hours
- Each token binds to one MAC address
- Check NVS storage if tokens aren't persisting

### Admin Panel Issues
- Ensure connected to ESP32 AP
- Use IP address (192.168.4.1), not domain name
- Clear browser cache if page doesn't update

## Security Considerations

⚠️ **Important**: This is a basic implementation intended for controlled environments.

- Change default admin password in production
- Consider implementing HTTPS for admin panel
- Token system uses simple alphanumeric strings
- No built-in brute force protection
- Open WiFi AP (no WPA encryption)

## Project Structure

```
esp32-portal-mesh/
├── main/
│   ├── main.c              # Main application code
│   └── CMakeLists.txt
├── CMakeLists.txt
├── sdkconfig               # ESP-IDF configuration
├── .gitignore
└── README.md
```

## License

This project is provided as-is for educational and development purposes.

## Credits

Built using ESP-IDF v5.3 and the ESP32 platform.

---

**Current Status**: Phase 2 complete - Admin panel and WiFi diagnostics working. Phase 3 (ESP-MESH) in development on `feature/mesh-network` branch.
