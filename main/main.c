#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_random.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_netif.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "lwip/ip_addr.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/opt.h"
#include "lwip/netif.h"
#include "lwip/lwip_napt.h"
#include "esp_mesh.h"
#include "esp_mesh_internal.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_sntp.h"
#include "esp_timer.h"
#include "heartbeat.h"

static const char *TAG = "esp32-mesh-portal";

// Time sync state
static bool time_synced = false;
static time_t time_sync_timestamp = 0;

// ==================== HTTP Response Constants ====================
// Common HTTP headers
#define HTTP_HEADER_JSON                 \
    "Content-Type: application/json\r\n" \
    "Connection: close\r\n\r\n"

// HTTP 403 Forbidden (API access from local network)
static const char HTTP_403_API_UPLINK_ONLY[] =
    "HTTP/1.1 403 Forbidden\r\n" HTTP_HEADER_JSON
    "{\"error\":\"API only accessible from uplink network\"}";

// HTTP 401 Unauthorized (Invalid API key)
static const char HTTP_401_INVALID_API_KEY[] =
    "HTTP/1.1 401 Unauthorized\r\n" HTTP_HEADER_JSON
    "{\"success\":false,\"error\":\"Invalid API key\"}";

// Helper macro to check if request is from local AP network
#define IS_LOCAL_AP_REQUEST(ip_str) (strncmp(ip_str, "192.168.4.", 10) == 0)

// Helper macro to send error and close connection
#define SEND_ERROR_AND_CLOSE(sock, response)       \
    do                                             \
    {                                              \
        send(sock, response, strlen(response), 0); \
        close(sock);                               \
    } while (0)

// Helper macro to reject local AP requests to API endpoints
#define REJECT_LOCAL_AP_REQUEST(sock, source_addr)                                         \
    do                                                                                     \
    {                                                                                      \
        char client_ip_str[16];                                                            \
        inet_ntop(AF_INET, &(source_addr).sin_addr, client_ip_str, sizeof(client_ip_str)); \
        if (IS_LOCAL_AP_REQUEST(client_ip_str))                                            \
        {                                                                                  \
            SEND_ERROR_AND_CLOSE(sock, HTTP_403_API_UPLINK_ONLY);                          \
            continue;                                                                      \
        }                                                                                  \
    } while (0)

// Helper macros
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

// Mesh configuration
#define MESH_ENABLED false           // Set to true to enable mesh networking
#define MESH_ID "ESP32-Guest-Portal" // This will be the visible SSID
#define MESH_PASSWORD "meshpass123"
#define MESH_CHANNEL 4 // Same as uplink WiFi channel
#define MESH_MAX_LAYER 6
#define MESH_ROUTER_SSID "TP-Link_521B"
#define MESH_ROUTER_PASS "08042024"

// Admin configuration
#define ADMIN_PASSWORD_KEY "admin_pass"
#define API_KEY_KEY "api_key"
#define WIFI_SSID_KEY "wifi_ssid"
#define WIFI_PASS_KEY "wifi_pass"
#define WIFI_USE_STATIC_IP_KEY "use_static"
#define WIFI_STATIC_IP_KEY "static_ip"
#define WIFI_STATIC_GATEWAY_KEY "static_gw"
#define WIFI_STATIC_NETMASK_KEY "static_nm"
#define WIFI_STATIC_DNS_KEY "static_dns"
#define ADMIN_SESSION_TIMEOUT 300 // 5 minutes in seconds
#define API_KEY_LENGTH 32

// Heartbeat LED configuration
#define HEARTBEAT_LED_GPIO GPIO_NUM_2 // Built-in LED on most ESP32 boards

// Current credentials (loaded from NVS or defaults)
static char admin_password[64] = "admin123";
static char api_key[API_KEY_LENGTH + 1] = {0};
static char current_wifi_ssid[32] = MESH_ROUTER_SSID;
static char current_wifi_pass[64] = MESH_ROUTER_PASS;

// Static IP configuration
static bool use_static_ip = false;
static char static_ip[16] = "192.168.1.100";
static char static_gateway[16] = "192.168.1.1";
static char static_netmask[16] = "255.255.255.0";
static char static_dns[16] = "8.8.8.8";

// Admin session management
static bool admin_logged_in = false;
static time_t last_admin_activity = 0;

// Mesh state
static bool mesh_connected = false;
static int mesh_layer = -1;

// Network interfaces
static esp_netif_t *sta_netif = NULL;
static esp_netif_t *ap_netif = NULL;

// Token management
#define TOKEN_LENGTH 8
#define TOKEN_EXPIRY_HOURS 24
#define MAX_TOKENS 230 // Increased from 50 to match NVS capacity (~231 max)
#define TOKEN_MIN_DURATION_MINUTES 30
#define TOKEN_MAX_DURATION_MINUTES (30 * 24 * 60) // 30 days
#define MAX_DEVICES_PER_TOKEN 2

typedef struct
{
    char token[TOKEN_LENGTH + 1];
    time_t created;
    time_t first_use;             // When token was first used (0 if not used yet)
    time_t last_use;              // Most recent usage timestamp (for multi-token handling)
    uint32_t duration_minutes;    // Duration from first use
    uint32_t bandwidth_down_mb;   // Download limit in MB
    uint32_t bandwidth_up_mb;     // Upload limit in MB
    uint32_t bandwidth_used_down; // Used download in MB
    uint32_t bandwidth_used_up;   // Used upload in MB
    uint32_t usage_count;
    uint8_t client_macs[MAX_DEVICES_PER_TOKEN][6]; // Multiple devices allowed
    uint8_t device_count;                          // Number of devices using this token
    bool active;
} token_info_t;

static token_info_t active_tokens[MAX_TOKENS];
static int token_count = 0;

// Authenticated clients tracking
#define MAX_AUTHENTICATED_CLIENTS 50
typedef struct
{
    uint32_t ip_addr; // Client IP address
    uint8_t mac[6];   // Client MAC address
    time_t auth_time; // When authenticated
    bool active;
} authenticated_client_t;

static authenticated_client_t authenticated_clients[MAX_AUTHENTICATED_CLIENTS];
static int authenticated_count = 0;

// Check if a client IP is authenticated
static bool is_client_authenticated(uint32_t client_ip)
{
    for (int i = 0; i < MAX_AUTHENTICATED_CLIENTS; i++)
    {
        if (authenticated_clients[i].active &&
            authenticated_clients[i].ip_addr == client_ip)
        {
            return true;
        }
    }
    return false;
}

// Add client to authenticated list
static void add_authenticated_client(uint32_t client_ip, const uint8_t *mac)
{
    // Check if already authenticated
    for (int i = 0; i < MAX_AUTHENTICATED_CLIENTS; i++)
    {
        if (authenticated_clients[i].active &&
            authenticated_clients[i].ip_addr == client_ip)
        {
            return; // Already authenticated
        }
    }

    // Find empty slot
    for (int i = 0; i < MAX_AUTHENTICATED_CLIENTS; i++)
    {
        if (!authenticated_clients[i].active)
        {
            authenticated_clients[i].ip_addr = client_ip;
            memcpy(authenticated_clients[i].mac, mac, 6);
            authenticated_clients[i].auth_time = time(NULL);
            authenticated_clients[i].active = true;
            authenticated_count++;
            ESP_LOGI(TAG, "✓ Client authenticated: " IPSTR, IP2STR((esp_ip4_addr_t *)&client_ip));
            return;
        }
    }
    ESP_LOGW(TAG, "Authenticated clients list full!");
}

// Helper function to count authenticated clients
static int get_authenticated_count(void)
{
    int count = 0;
    for (int i = 0; i < MAX_AUTHENTICATED_CLIENTS; i++)
    {
        if (authenticated_clients[i].active)
        {
            count++;
        }
    }
    return count;
}

// Helper function to count active tokens
static int get_active_token_count(void)
{
    int count = 0;
    for (int i = 0; i < MAX_TOKENS; i++)
    {
        if (active_tokens[i].active)
        {
            count++;
        }
    }
    return count;
}

#if MESH_ENABLED
// ESP-MESH event handler
static void mesh_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    mesh_addr_t id = {0};

    switch (event_id)
    {
    case MESH_EVENT_STARTED:
        esp_mesh_get_id(&id);
        ESP_LOGI(TAG, "<MESH_EVENT_STARTED> Mesh network started");
        mesh_connected = false;
        break;

    case MESH_EVENT_STOPPED:
        ESP_LOGI(TAG, "<MESH_EVENT_STOPPED> Mesh network stopped");
        mesh_connected = false;
        break;

    case MESH_EVENT_CHILD_CONNECTED:
    {
        ESP_LOGI(TAG, "<MESH_EVENT_CHILD_CONNECTED>");
        break;
    }

    case MESH_EVENT_CHILD_DISCONNECTED:
    {
        ESP_LOGI(TAG, "<MESH_EVENT_CHILD_DISCONNECTED>");
        break;
    }

    case MESH_EVENT_ROUTING_TABLE_ADD:
    {
        mesh_event_routing_table_change_t *routing_table = (mesh_event_routing_table_change_t *)event_data;
        ESP_LOGI(TAG, "<MESH_EVENT_ROUTING_TABLE_ADD> Routing table size: %d",
                 routing_table->rt_size_new);
        break;
    }

    case MESH_EVENT_ROUTING_TABLE_REMOVE:
    {
        mesh_event_routing_table_change_t *routing_table = (mesh_event_routing_table_change_t *)event_data;
        ESP_LOGI(TAG, "<MESH_EVENT_ROUTING_TABLE_REMOVE> Routing table size: %d",
                 routing_table->rt_size_new);
        break;
    }

    case MESH_EVENT_PARENT_CONNECTED:
    {
        mesh_event_connected_t *connected = (mesh_event_connected_t *)event_data;
        esp_mesh_get_id(&id);
        mesh_layer = connected->self_layer;
        ESP_LOGI(TAG, "<MESH_EVENT_PARENT_CONNECTED> Layer: %d", mesh_layer);
        mesh_connected = true;

        // If we're root node, we already have internet via STA
        if (esp_mesh_is_root())
        {
            ESP_LOGI(TAG, "✓ MESH ROOT NODE: Acting as internet gateway");
        }
        break;
    }

    case MESH_EVENT_PARENT_DISCONNECTED:
    {
        mesh_event_disconnected_t *disconnected = (mesh_event_disconnected_t *)event_data;
        ESP_LOGI(TAG, "<MESH_EVENT_PARENT_DISCONNECTED> Layer: %d, Reason: %d",
                 mesh_layer, disconnected->reason);
        mesh_connected = false;
        mesh_layer = esp_mesh_get_layer();
        break;
    }

    case MESH_EVENT_LAYER_CHANGE:
    {
        mesh_event_layer_change_t *layer_change = (mesh_event_layer_change_t *)event_data;
        int old = mesh_layer;
        mesh_layer = layer_change->new_layer;
        ESP_LOGI(TAG, "<MESH_EVENT_LAYER_CHANGE> Layer changed: %d -> %d",
                 old, layer_change->new_layer);
        break;
    }

    case MESH_EVENT_ROOT_ADDRESS:
    {
        ESP_LOGI(TAG, "<MESH_EVENT_ROOT_ADDRESS> received");
        break;
    }

    case MESH_EVENT_ROOT_FIXED:
    {
        mesh_event_root_fixed_t *root_fixed = (mesh_event_root_fixed_t *)event_data;
        ESP_LOGI(TAG, "<MESH_EVENT_ROOT_FIXED> Root fixed: %s",
                 root_fixed->is_fixed ? "YES" : "NO");
        break;
    }

    default:
        break;
    }
}
#endif // MESH_ENABLED

// Generate random alphanumeric token
static void generate_token(char *token_out)
{
    const char charset[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Excludes confusing chars
    for (int i = 0; i < TOKEN_LENGTH; i++)
    {
        uint32_t rand = esp_random();
        token_out[i] = charset[rand % (sizeof(charset) - 1)];
    }
    token_out[TOKEN_LENGTH] = '\0';
}

// Generate random API key
static void generate_api_key(char *key_out)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < API_KEY_LENGTH; i++)
    {
        uint32_t rand = esp_random();
        key_out[i] = charset[rand % (sizeof(charset) - 1)];
    }
    key_out[API_KEY_LENGTH] = '\0';
}

// Save token to NVS
static esp_err_t save_token_to_nvs(const char *token, token_info_t *info)
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("tokens", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Error opening NVS for tokens: %s", esp_err_to_name(err));
        return err;
    }

    // Save token info as blob
    err = nvs_set_blob(nvs_handle, token, info, sizeof(token_info_t));
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Error saving token to NVS: %s", esp_err_to_name(err));
    }
    else
    {
        err = nvs_commit(nvs_handle);
        ESP_LOGI(TAG, "Token %s saved to NVS (expires in %d hours)", token, TOKEN_EXPIRY_HOURS);
    }

    nvs_close(nvs_handle);
    return err;
}

// Load all tokens from NVS
static void load_tokens_from_nvs(void)
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("tokens", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGI(TAG, "No existing tokens found in NVS");
        return;
    }

    nvs_iterator_t it = NULL;
    err = nvs_entry_find("nvs", "tokens", NVS_TYPE_BLOB, &it);
    token_count = 0;

    while (err == ESP_OK && token_count < MAX_TOKENS)
    {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);

        size_t required_size = sizeof(token_info_t);
        err = nvs_get_blob(nvs_handle, info.key, &active_tokens[token_count], &required_size);

        if (err == ESP_OK && active_tokens[token_count].active)
        {
            // Check if token has expired
            time_t now = time(NULL);
            bool expired = false;

            if (active_tokens[token_count].first_use > 0)
            {
                time_t token_expires = active_tokens[token_count].first_use +
                                       (active_tokens[token_count].duration_minutes * 60);
                if (now > token_expires)
                {
                    ESP_LOGI(TAG, "Token %s expired (time), removing", active_tokens[token_count].token);
                    expired = true;
                }
            }

            // Check bandwidth limits
            if (active_tokens[token_count].bandwidth_down_mb > 0 &&
                active_tokens[token_count].bandwidth_used_down >= active_tokens[token_count].bandwidth_down_mb)
            {
                ESP_LOGI(TAG, "Token %s expired (bandwidth down), removing", active_tokens[token_count].token);
                expired = true;
            }
            if (active_tokens[token_count].bandwidth_up_mb > 0 &&
                active_tokens[token_count].bandwidth_used_up >= active_tokens[token_count].bandwidth_up_mb)
            {
                ESP_LOGI(TAG, "Token %s expired (bandwidth up), removing", active_tokens[token_count].token);
                expired = true;
            }

            if (expired)
            {
                active_tokens[token_count].active = false;
            }
            else
            {
                ESP_LOGI(TAG, "Loaded token %s (used %lu times, %d devices)",
                         active_tokens[token_count].token,
                         active_tokens[token_count].usage_count,
                         active_tokens[token_count].device_count);
                token_count++;
            }
        }

        err = nvs_entry_next(&it);
    }

    if (it != NULL)
    {
        nvs_release_iterator(it);
    }

    nvs_close(nvs_handle);
    ESP_LOGI(TAG, "Loaded %d active tokens from NVS", token_count);
}

// Check if system time is synced and valid
static bool is_time_valid(void)
{
    if (!time_synced)
    {
        return false;
    }

    // Check if sync was recent (within 24 hours)
    time_t now = time(NULL);
    if (now - time_sync_timestamp > 86400)
    {
        ESP_LOGW(TAG, "Time sync is stale (>24h old)");
        return false;
    }

    return true;
}

// Create new access token with parameters
static esp_err_t create_new_token_with_params(char *token_out, uint32_t duration_minutes,
                                              uint32_t bandwidth_down_mb, uint32_t bandwidth_up_mb)
{
    // Check if time is valid before creating token
    if (!is_time_valid())
    {
        ESP_LOGW(TAG, "Cannot create token: system time not synced");
        return ESP_ERR_INVALID_STATE;
    }

    if (token_count >= MAX_TOKENS)
    {
        ESP_LOGE(TAG, "Maximum token limit reached: token_count=%d, MAX_TOKENS=%d",
                 token_count, MAX_TOKENS);
        return ESP_ERR_NO_MEM;
    }

    // Validate duration
    if (duration_minutes < TOKEN_MIN_DURATION_MINUTES || duration_minutes > TOKEN_MAX_DURATION_MINUTES)
    {
        ESP_LOGE(TAG, "Invalid duration: %lu minutes (must be %d-%d)",
                 duration_minutes, TOKEN_MIN_DURATION_MINUTES, TOKEN_MAX_DURATION_MINUTES);
        return ESP_ERR_INVALID_ARG;
    }

    token_info_t new_token;
    generate_token(new_token.token);

    time_t now = time(NULL);
    new_token.created = now;
    new_token.first_use = 0; // Not used yet
    new_token.last_use = 0;  // Not used yet
    new_token.duration_minutes = duration_minutes;
    new_token.bandwidth_down_mb = bandwidth_down_mb;
    new_token.bandwidth_up_mb = bandwidth_up_mb;
    new_token.bandwidth_used_down = 0;
    new_token.bandwidth_used_up = 0;
    new_token.usage_count = 0;
    memset(new_token.client_macs, 0, sizeof(new_token.client_macs));
    new_token.device_count = 0;
    new_token.active = true;

    // Save to NVS
    esp_err_t err = save_token_to_nvs(new_token.token, &new_token);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to create token - NVS save error: %s (0x%x)",
                 esp_err_to_name(err), err);
        return err;
    }

    // Add to active tokens
    memcpy(&active_tokens[token_count], &new_token, sizeof(token_info_t));
    token_count++;

    strcpy(token_out, new_token.token);
    ESP_LOGI(TAG, "✓ Created new token: %s (duration: %lu min, down: %lu MB, up: %lu MB)",
             token_out, duration_minutes, bandwidth_down_mb, bandwidth_up_mb);

    return ESP_OK;
}

// Create new access token (simple version for admin UI)
static esp_err_t create_new_token(char *token_out)
{
    // Default: 24 hours, unlimited bandwidth
    return create_new_token_with_params(token_out, TOKEN_EXPIRY_HOURS * 60, 0, 0);
}

// Validate token and bind to client MAC
static bool validate_token(const char *token, const uint8_t *client_mac)
{
    // Cannot validate tokens without valid time
    if (!is_time_valid())
    {
        ESP_LOGW(TAG, "Cannot validate token: system time not synced");
        return false;
    }

    time_t now = time(NULL);
    ESP_LOGI(TAG, "DEBUG: validate_token - now=%lld, time_synced=%d", (long long)now, time_synced);

    for (int i = 0; i < token_count; i++)
    {
        if (!active_tokens[i].active)
            continue;

        if (strcmp(active_tokens[i].token, token) == 0)
        {
            // Set first use time if not set
            if (active_tokens[i].first_use == 0)
            {
                active_tokens[i].first_use = now;
                ESP_LOGI(TAG, "Token %s first use at %lld (now=%lld)", token, (long long)active_tokens[i].first_use, (long long)now);
            }

            // Update last use time on every validation (for multi-token handling)
            active_tokens[i].last_use = now;

            // Check time-based expiration (from first use)
            time_t token_expires = active_tokens[i].first_use + (active_tokens[i].duration_minutes * 60);
            if (now > token_expires)
            {
                ESP_LOGW(TAG, "Token %s has expired (time limit)", token);
                active_tokens[i].active = false;
                save_token_to_nvs(active_tokens[i].token, &active_tokens[i]);
                return false;
            }

            // Check bandwidth expiration
            if (active_tokens[i].bandwidth_down_mb > 0 &&
                active_tokens[i].bandwidth_used_down >= active_tokens[i].bandwidth_down_mb)
            {
                ESP_LOGW(TAG, "Token %s exceeded download limit", token);
                active_tokens[i].active = false;
                save_token_to_nvs(active_tokens[i].token, &active_tokens[i]);
                return false;
            }
            if (active_tokens[i].bandwidth_up_mb > 0 &&
                active_tokens[i].bandwidth_used_up >= active_tokens[i].bandwidth_up_mb)
            {
                ESP_LOGW(TAG, "Token %s exceeded upload limit", token);
                active_tokens[i].active = false;
                save_token_to_nvs(active_tokens[i].token, &active_tokens[i]);
                return false;
            }

            // Check if this MAC is already registered
            int mac_index = -1;
            for (int j = 0; j < active_tokens[i].device_count; j++)
            {
                if (memcmp(active_tokens[i].client_macs[j], client_mac, 6) == 0)
                {
                    mac_index = j;
                    break;
                }
            }

            if (mac_index == -1)
            {
                // New device - check if we can add it
                if (active_tokens[i].device_count >= MAX_DEVICES_PER_TOKEN)
                {
                    ESP_LOGW(TAG, "Token %s already has %d devices (max allowed)",
                             token, MAX_DEVICES_PER_TOKEN);
                    return false;
                }

                // Add this MAC
                memcpy(active_tokens[i].client_macs[active_tokens[i].device_count], client_mac, 6);
                active_tokens[i].device_count++;
                ESP_LOGI(TAG, "Token %s bound to device %d: %02X:%02X:%02X:%02X:%02X:%02X",
                         token, active_tokens[i].device_count,
                         client_mac[0], client_mac[1], client_mac[2],
                         client_mac[3], client_mac[4], client_mac[5]);
            }

            // Increment usage count
            active_tokens[i].usage_count++;
            save_token_to_nvs(active_tokens[i].token, &active_tokens[i]);

            ESP_LOGI(TAG, "✓ Token %s validated (usage: %lu)", token, active_tokens[i].usage_count);
            return true;
        }
    }

    ESP_LOGW(TAG, "✗ Invalid token: %s", token);
    return false;
}

// Get token info by token string (helper function)
static token_info_t *get_token_info_by_string(const char *token)
{
    for (int i = 0; i < token_count; i++)
    {
        if (active_tokens[i].active && strcmp(active_tokens[i].token, token) == 0)
        {
            return &active_tokens[i];
        }
    }
    return NULL;
}

// Periodic cleanup of expired tokens
// Called every 30s by SNTP sync callback
static void cleanup_expired_tokens(void)
{
    if (!is_time_valid())
    {
        return; // Skip cleanup if time not yet valid
    }

    time_t now = time(NULL);
    int cleaned = 0;

    for (int i = 0; i < token_count; i++)
    {
        if (!active_tokens[i].active)
        {
            continue;
        }

        bool expired = false;
        const char *reason = NULL;

        // Check time-based expiration
        if (active_tokens[i].first_use > 0)
        {
            time_t token_expires = active_tokens[i].first_use +
                                   (active_tokens[i].duration_minutes * 60);
            if (now > token_expires)
            {
                expired = true;
                reason = "time limit";
            }
        }

        // Check bandwidth limits
        if (!expired && active_tokens[i].bandwidth_down_mb > 0 &&
            active_tokens[i].bandwidth_used_down >= active_tokens[i].bandwidth_down_mb)
        {
            expired = true;
            reason = "bandwidth down limit";
        }

        if (!expired && active_tokens[i].bandwidth_up_mb > 0 &&
            active_tokens[i].bandwidth_used_up >= active_tokens[i].bandwidth_up_mb)
        {
            expired = true;
            reason = "bandwidth up limit";
        }

        if (expired)
        {
            ESP_LOGI(TAG, "🧹 Cleaning up expired token %s (%s)",
                     active_tokens[i].token, reason);

            // Mark as inactive in memory
            active_tokens[i].active = false;

            // Remove from NVS
            nvs_handle_t nvs_handle;
            if (nvs_open("tokens", NVS_READWRITE, &nvs_handle) == ESP_OK)
            {
                nvs_erase_key(nvs_handle, active_tokens[i].token);
                nvs_commit(nvs_handle);
                nvs_close(nvs_handle);
            }

            cleaned++;
        }
    }

    // Compact the active tokens array by removing inactive entries
    if (cleaned > 0)
    {
        int write_idx = 0;
        for (int read_idx = 0; read_idx < token_count; read_idx++)
        {
            if (active_tokens[read_idx].active)
            {
                if (write_idx != read_idx)
                {
                    active_tokens[write_idx] = active_tokens[read_idx];
                }
                write_idx++;
            }
        }
        token_count = write_idx;

        ESP_LOGI(TAG, "🧹 Cleanup complete: %d token(s) removed, %d active token(s) remaining",
                 cleaned, token_count);
    }
}

// SNTP sync notification callback
static void time_sync_notification_cb(struct timeval *tv)
{
    time_synced = true;
    time_sync_timestamp = tv->tv_sec;

    char time_str[64];
    struct tm *timeinfo = localtime(&tv->tv_sec);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S UTC", timeinfo);
    ESP_LOGI(TAG, "✓ Time synchronized via SNTP: %s", time_str);

    // Switch LED to slow heartbeat (connected mode) now that time is synced
    heartbeat_set_connected(true);
    ESP_LOGI(TAG, "✓ Heartbeat: Slow blink (internet connected, time synced)");

    // Cleanup expired tokens every 30s (on each SNTP sync)
    cleanup_expired_tokens();
}

// Initialize SNTP time synchronization
static void initialize_sntp(void)
{
    ESP_LOGI(TAG, "Initializing SNTP time sync...");

    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_setservername(1, "time.google.com");
    esp_sntp_setservername(2, "time.cloudflare.com");
    esp_sntp_init();

    // Set timezone to UTC
    setenv("TZ", "UTC", 1);
    tzset();

    ESP_LOGI(TAG, "Waiting for time sync from NTP servers...");
}

// Task to poll SNTP every 30 seconds
static void sntp_poll_task(void *pvParameters)
{
    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(30000)); // 30 seconds

        if (sta_netif != NULL)
        {
            esp_netif_ip_info_t ip_info;
            if (esp_netif_get_ip_info(sta_netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0)
            {
                // We have internet, request time sync
                esp_sntp_restart();
            }
        }
    }
}

// Get token info by client MAC address
static token_info_t *get_token_info_by_mac(const uint8_t *mac)
{
    token_info_t *most_recent_token = NULL;
    time_t most_recent_use = 0;

    // Find all tokens with this MAC and return the one used most recently
    for (int i = 0; i < token_count; i++)
    {
        if (!active_tokens[i].active)
            continue;

        // Check if this MAC is registered with the token
        for (int j = 0; j < active_tokens[i].device_count; j++)
        {
            if (memcmp(active_tokens[i].client_macs[j], mac, 6) == 0)
            {
                // Found a token with this MAC - check if it's the most recent
                if (active_tokens[i].last_use > most_recent_use)
                {
                    most_recent_use = active_tokens[i].last_use;
                    most_recent_token = &active_tokens[i];
                }
                break; // Move to next token
            }
        }
    }

    if (most_recent_token != NULL)
    {
        ESP_LOGI(TAG, "Found token %s for MAC (last_use=%lld)",
                 most_recent_token->token, (long long)most_recent_use);
    }

    return most_recent_token;
}

// Send stats page for authenticated user
static void send_stats_page(int sock, const char *token_str, token_info_t *token_info)
{
    // Calculate remaining time
    time_t now = time(NULL);
    time_t expires_at = token_info->first_use + (token_info->duration_minutes * 60);
    time_t time_remaining = expires_at - now;
    int hours_left = time_remaining / 3600;
    int minutes_left = (time_remaining % 3600) / 60;

    // Debug logging
    ESP_LOGI(TAG, "DEBUG: send_stats_page - first_use=%lld, now=%lld, expires_at=%lld, time_remaining=%lld, duration_minutes=%ld",
             (long long)token_info->first_use, (long long)now, (long long)expires_at,
             (long long)time_remaining, (long)token_info->duration_minutes);

    // Format expiration date
    struct tm *exp_time = localtime(&expires_at);
    char exp_str[64];
    strftime(exp_str, sizeof(exp_str), "%b %d, %Y %I:%M %p", exp_time);

    // Build success response with detailed stats
    char response[3072];
    int offset = snprintf(response, sizeof(response),
                          "HTTP/1.1 200 OK\r\n"
                          "Content-Type: text/html; charset=UTF-8\r\n"
                          "Connection: close\r\n\r\n"
                          "<!DOCTYPE html>"
                          "<html><head><meta charset='UTF-8'><title>Connected</title>"
                          "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                          "<style>"
                          "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;margin:0;padding:20px;background:linear-gradient(135deg,#667eea 0%%,#764ba2 100%%);min-height:100vh;display:flex;align-items:center;justify-content:center}"
                          ".box{background:white;padding:30px;border-radius:15px;box-shadow:0 10px 40px rgba(0,0,0,0.2);max-width:400px;width:100%%}"
                          "h1{color:#28a745;margin:0 0 10px 0;font-size:28px}h1::before{content:'✓ ';font-size:32px}"
                          "p{color:#666;margin:0 0 20px 0}"
                          ".divider{border-top:2px solid #f0f0f0;margin:20px 0}"
                          ".token-code{background:#f8f9fa;padding:12px;border-radius:8px;font-family:monospace;font-size:18px;font-weight:bold;text-align:center;letter-spacing:2px;margin:15px 0;color:#333}"
                          ".stat-group{margin:15px 0}"
                          ".stat-label{font-size:20px;margin-right:8px}"
                          ".stat-title{font-weight:600;color:#333;margin-bottom:8px;display:flex;align-items:center}"
                          ".stat-value{color:#666;font-size:14px;margin-left:28px}"
                          ".time-remaining{font-size:24px;font-weight:bold;color:#28a745;margin:5px 0}"
                          ".expires{color:#999;font-size:12px}"
                          ".usage-badge{display:inline-block;background:#e7f3ff;color:#0066cc;padding:4px 12px;border-radius:12px;font-size:12px;font-weight:600;margin:5px 5px 5px 28px}"
                          ".unlimited{color:#28a745;font-weight:600}"
                          "</style></head><body><div class='box'>"
                          "<h1>Connected!</h1>"
                          "<p>Your device is now connected to the internet</p>"
                          "<div class='divider'></div>"
                          "<div class='token-code'>%s</div>",
                          token_str);

    // Time remaining section
    offset += snprintf(response + offset, sizeof(response) - offset,
                       "<div class='stat-group'>"
                       "<div class='stat-title'><span class='stat-label'>⏱️</span> Time Remaining</div>"
                       "<div class='time-remaining'>%dh %dm</div>"
                       "<div class='expires'>Expires: %s</div>"
                       "</div>",
                       hours_left, minutes_left, exp_str);

    // Usage statistics section
    offset += snprintf(response + offset, sizeof(response) - offset,
                       "<div class='stat-group'>"
                       "<div class='stat-title'><span class='stat-label'>📊</span> Usage Statistics</div>"
                       "<div class='usage-badge'>Used %lu times</div>"
                       "<div class='usage-badge'>Device %d of %d</div>"
                       "</div>",
                       token_info->usage_count, token_info->device_count, MAX_DEVICES_PER_TOKEN);

    // Bandwidth section
    offset += snprintf(response + offset, sizeof(response) - offset,
                       "<div class='stat-group'>"
                       "<div class='stat-title'><span class='stat-label'>📶</span> Bandwidth</div>");

    if (token_info->bandwidth_down_mb == 0)
    {
        offset += snprintf(response + offset, sizeof(response) - offset,
                           "<div class='stat-value'>Download: <span class='unlimited'>Unlimited</span></div>");
    }
    else
    {
        offset += snprintf(response + offset, sizeof(response) - offset,
                           "<div class='stat-value'>Download: %lu / %lu MB</div>",
                           token_info->bandwidth_used_down, token_info->bandwidth_down_mb);
    }

    if (token_info->bandwidth_up_mb == 0)
    {
        offset += snprintf(response + offset, sizeof(response) - offset,
                           "<div class='stat-value'>Upload: <span class='unlimited'>Unlimited</span></div>");
    }
    else
    {
        offset += snprintf(response + offset, sizeof(response) - offset,
                           "<div class='stat-value'>Upload: %lu / %lu MB</div>",
                           token_info->bandwidth_used_up, token_info->bandwidth_up_mb);
    }

    offset += snprintf(response + offset, sizeof(response) - offset,
                       "</div></div></body></html>");

    send(sock, response, strlen(response), 0);
}

// Load or generate API key
static void load_or_generate_api_key(void)
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("config", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Error opening NVS for API key");
        return;
    }

    size_t key_len = sizeof(api_key);
    err = nvs_get_str(nvs_handle, API_KEY_KEY, api_key, &key_len);

    if (err == ESP_ERR_NVS_NOT_FOUND)
    {
        // Generate new API key
        generate_api_key(api_key);
        nvs_set_str(nvs_handle, API_KEY_KEY, api_key);
        nvs_commit(nvs_handle);
        ESP_LOGI(TAG, "Generated new API key: %s", api_key);
    }
    else if (err == ESP_OK)
    {
        ESP_LOGI(TAG, "Loaded API key from NVS");
    }
    else
    {
        ESP_LOGE(TAG, "Error loading API key: %s", esp_err_to_name(err));
    }

    nvs_close(nvs_handle);
}

// Regenerate API key (for admin UI)
static esp_err_t regenerate_api_key(void)
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("config", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK)
    {
        return err;
    }

    generate_api_key(api_key);
    err = nvs_set_str(nvs_handle, API_KEY_KEY, api_key);
    if (err == ESP_OK)
    {
        err = nvs_commit(nvs_handle);
        ESP_LOGI(TAG, "Regenerated API key");
    }

    nvs_close(nvs_handle);
    return err;
}

// Load admin password from NVS
static void load_admin_password(void)
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("config", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGI(TAG, "No saved admin password, using default");
        strcpy(admin_password, "admin123");
        return;
    }

    size_t pass_len = sizeof(admin_password);
    err = nvs_get_str(nvs_handle, ADMIN_PASSWORD_KEY, admin_password, &pass_len);

    if (err == ESP_ERR_NVS_NOT_FOUND)
    {
        strcpy(admin_password, "admin123");
        ESP_LOGI(TAG, "No saved admin password, using default");
    }
    else if (err == ESP_OK)
    {
        ESP_LOGI(TAG, "Loaded admin password from NVS");
    }

    nvs_close(nvs_handle);
}

// Change admin password
static esp_err_t change_admin_password(const char *old_pass, const char *new_pass)
{
    // Verify old password
    if (strcmp(admin_password, old_pass) != 0)
    {
        ESP_LOGW(TAG, "Old password incorrect");
        return ESP_ERR_INVALID_ARG;
    }

    // Validate new password (minimum 6 characters)
    if (strlen(new_pass) < 6)
    {
        ESP_LOGW(TAG, "New password too short");
        return ESP_ERR_INVALID_SIZE;
    }

    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("config", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK)
    {
        return err;
    }

    err = nvs_set_str(nvs_handle, ADMIN_PASSWORD_KEY, new_pass);
    if (err == ESP_OK)
    {
        err = nvs_commit(nvs_handle);
        if (err == ESP_OK)
        {
            strcpy(admin_password, new_pass);
            ESP_LOGI(TAG, "Admin password changed successfully");
        }
    }

    nvs_close(nvs_handle);
    return err;
}

// Check admin session validity
static bool is_admin_session_valid(void)
{
    if (!admin_logged_in)
    {
        return false;
    }

    time_t now = time(NULL);
    if ((now - last_admin_activity) > ADMIN_SESSION_TIMEOUT)
    {
        admin_logged_in = false;
        ESP_LOGI(TAG, "Admin session expired");
        return false;
    }

    return true;
}

// Update admin activity timestamp
static void update_admin_activity(void)
{
    last_admin_activity = time(NULL);
}

// Load WiFi credentials from NVS
static void load_wifi_credentials(void)
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("config", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGI(TAG, "No saved WiFi credentials, using defaults");
        return;
    }

    size_t ssid_len = sizeof(current_wifi_ssid);
    size_t pass_len = sizeof(current_wifi_pass);

    err = nvs_get_str(nvs_handle, WIFI_SSID_KEY, current_wifi_ssid, &ssid_len);
    if (err == ESP_OK)
    {
        ESP_LOGI(TAG, "Loaded WiFi SSID: %s", current_wifi_ssid);
    }

    err = nvs_get_str(nvs_handle, WIFI_PASS_KEY, current_wifi_pass, &pass_len);
    if (err == ESP_OK)
    {
        ESP_LOGI(TAG, "Loaded WiFi password from NVS");
    }

    // Load static IP configuration
    uint8_t use_static = 0;
    err = nvs_get_u8(nvs_handle, WIFI_USE_STATIC_IP_KEY, &use_static);
    if (err == ESP_OK)
    {
        use_static_ip = (use_static == 1);
        ESP_LOGI(TAG, "IP Mode: %s", use_static_ip ? "Static" : "DHCP");

        if (use_static_ip)
        {
            size_t len = sizeof(static_ip);
            nvs_get_str(nvs_handle, WIFI_STATIC_IP_KEY, static_ip, &len);
            len = sizeof(static_gateway);
            nvs_get_str(nvs_handle, WIFI_STATIC_GATEWAY_KEY, static_gateway, &len);
            len = sizeof(static_netmask);
            nvs_get_str(nvs_handle, WIFI_STATIC_NETMASK_KEY, static_netmask, &len);
            len = sizeof(static_dns);
            nvs_get_str(nvs_handle, WIFI_STATIC_DNS_KEY, static_dns, &len);

            ESP_LOGI(TAG, "Static IP: %s, Gateway: %s, Netmask: %s, DNS: %s",
                     static_ip, static_gateway, static_netmask, static_dns);
        }
    }

    nvs_close(nvs_handle);
}

// Save WiFi credentials to NVS
static esp_err_t save_wifi_credentials(const char *ssid, const char *password)
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("config", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Error opening NVS for WiFi config: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_set_str(nvs_handle, WIFI_SSID_KEY, ssid);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Error saving WiFi SSID: %s", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return err;
    }

    err = nvs_set_str(nvs_handle, WIFI_PASS_KEY, password);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Error saving WiFi password: %s", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return err;
    }

    err = nvs_commit(nvs_handle);
    nvs_close(nvs_handle);

    if (err == ESP_OK)
    {
        ESP_LOGI(TAG, "✓ WiFi credentials saved: %s", ssid);
        // Update current credentials
        strncpy(current_wifi_ssid, ssid, sizeof(current_wifi_ssid) - 1);
        strncpy(current_wifi_pass, password, sizeof(current_wifi_pass) - 1);
    }

    return err;
}

// Save static IP configuration to NVS
static esp_err_t save_static_ip_config(bool use_static, const char *ip,
                                       const char *gateway, const char *netmask, const char *dns)
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("config", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Error opening NVS for IP config: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_set_u8(nvs_handle, WIFI_USE_STATIC_IP_KEY, use_static ? 1 : 0);
    if (err == ESP_OK && use_static)
    {
        nvs_set_str(nvs_handle, WIFI_STATIC_IP_KEY, ip);
        nvs_set_str(nvs_handle, WIFI_STATIC_GATEWAY_KEY, gateway);
        nvs_set_str(nvs_handle, WIFI_STATIC_NETMASK_KEY, netmask);
        nvs_set_str(nvs_handle, WIFI_STATIC_DNS_KEY, dns);
    }

    err = nvs_commit(nvs_handle);
    nvs_close(nvs_handle);

    if (err == ESP_OK)
    {
        use_static_ip = use_static;
        if (use_static)
        {
            strncpy(static_ip, ip, sizeof(static_ip) - 1);
            strncpy(static_gateway, gateway, sizeof(static_gateway) - 1);
            strncpy(static_netmask, netmask, sizeof(static_netmask) - 1);
            strncpy(static_dns, dns, sizeof(static_dns) - 1);
            ESP_LOGI(TAG, "✓ Static IP config saved: IP=%s, GW=%s, NM=%s, DNS=%s",
                     ip, gateway, netmask, dns);
        }
        else
        {
            ESP_LOGI(TAG, "✓ DHCP mode enabled");
        }
    }

    return err;
}

// WiFi connection tracking
static int wifi_retry_num = 0;
#define MAX_WIFI_RETRY 5

// Reconnect WiFi with new credentials
static void reconnect_wifi(void)
{
    ESP_LOGI(TAG, "Reconnecting WiFi with new credentials...");

    // Reset retry counter
    wifi_retry_num = 0;

    // Stop DHCP client first if switching to static IP
    if (use_static_ip && sta_netif != NULL)
    {
        esp_netif_dhcpc_stop(sta_netif);

        // Configure static IP
        esp_netif_ip_info_t ip_info;
        memset(&ip_info, 0, sizeof(esp_netif_ip_info_t));

        ip_info.ip.addr = esp_ip4addr_aton(static_ip);
        ip_info.gw.addr = esp_ip4addr_aton(static_gateway);
        ip_info.netmask.addr = esp_ip4addr_aton(static_netmask);

        esp_netif_set_ip_info(sta_netif, &ip_info);

        // Set DNS
        esp_netif_dns_info_t dns_info;
        dns_info.ip.u_addr.ip4.addr = esp_ip4addr_aton(static_dns);
        dns_info.ip.type = IPADDR_TYPE_V4;
        esp_netif_set_dns_info(sta_netif, ESP_NETIF_DNS_MAIN, &dns_info);

        ESP_LOGI(TAG, "Static IP configured: %s", static_ip);
    }
    else if (!use_static_ip && sta_netif != NULL)
    {
        // Enable DHCP client
        esp_netif_dhcpc_start(sta_netif);
        ESP_LOGI(TAG, "DHCP client enabled");
    }

    // Disconnect current STA connection
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(1000));

    // Update WiFi configuration
    wifi_config_t wifi_config_sta = {0};
    strncpy((char *)wifi_config_sta.sta.ssid, current_wifi_ssid, sizeof(wifi_config_sta.sta.ssid));
    strncpy((char *)wifi_config_sta.sta.password, current_wifi_pass, sizeof(wifi_config_sta.sta.password));

    esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &wifi_config_sta);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to set WiFi config: %s", esp_err_to_name(err));
        return;
    }

    // Reconnect
    err = esp_wifi_connect();
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to connect WiFi: %s", esp_err_to_name(err));
    }
    else
    {
        ESP_LOGI(TAG, "WiFi reconnection initiated");
    }
}

// Enable NAT for internet routing
static void enable_nat_routing(void)
{
    if (ap_netif == NULL || sta_netif == NULL)
    {
        ESP_LOGW(TAG, "Cannot enable NAT: interfaces not initialized");
        return;
    }

    esp_netif_ip_info_t ap_ip_info;
    esp_netif_get_ip_info(ap_netif, &ap_ip_info);

    esp_netif_ip_info_t sta_ip_info;
    esp_netif_get_ip_info(sta_netif, &sta_ip_info);

    if (sta_ip_info.ip.addr != 0)
    {
        // Enable NAPT on the AP interface
        ip_napt_enable(ap_ip_info.ip.addr, 1);
        ESP_LOGI(TAG, "✓ NAT ENABLED on AP: " IPSTR " forwarding through STA: " IPSTR,
                 IP2STR(&ap_ip_info.ip), IP2STR(&sta_ip_info.ip));
    }
    else
    {
        ESP_LOGW(TAG, "NAT not enabled: STA has no IP address yet");
    }
}

// WiFi event handler
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
    {
        ESP_LOGI(TAG, "WiFi STA starting, attempting connection to: %s", current_wifi_ssid);
        esp_wifi_connect();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
    {
        wifi_event_sta_disconnected_t *disconnected = (wifi_event_sta_disconnected_t *)event_data;
        ESP_LOGW(TAG, "WiFi disconnected, reason: %d", disconnected->reason);

        // Log specific disconnect reasons
        switch (disconnected->reason)
        {
        case WIFI_REASON_AUTH_EXPIRE:
        case WIFI_REASON_AUTH_LEAVE:
        case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
        case WIFI_REASON_HANDSHAKE_TIMEOUT:
            ESP_LOGE(TAG, "✗ Authentication failed - check password for SSID: %s", current_wifi_ssid);
            break;
        case WIFI_REASON_NO_AP_FOUND:
            ESP_LOGE(TAG, "✗ AP not found - check SSID: %s", current_wifi_ssid);
            break;
        case WIFI_REASON_ASSOC_FAIL:
            ESP_LOGE(TAG, "✗ Association failed - router might be rejecting connection");
            break;
        default:
            ESP_LOGW(TAG, "Disconnect reason code: %d", disconnected->reason);
            break;
        }

        // Switch LED back to fast blink (disconnected mode)
        heartbeat_set_connected(false);
        ESP_LOGI(TAG, "✓ Heartbeat: Fast blink (WiFi disconnected)");

        if (wifi_retry_num < MAX_WIFI_RETRY)
        {
            esp_wifi_connect();
            wifi_retry_num++;
            ESP_LOGI(TAG, "Retry connecting to AP, attempt %d/%d", wifi_retry_num, MAX_WIFI_RETRY);
        }
        else
        {
            ESP_LOGE(TAG, "✗ Failed to connect to '%s' after %d attempts - please check credentials in admin panel",
                     current_wifi_ssid, MAX_WIFI_RETRY);
        }
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "✓✓✓ INTERNET CONNECTED ✓✓✓ Got IP address: " IPSTR, IP2STR(&event->ip_info.ip));
        ESP_LOGI(TAG, "✓ STA connected to: %s", current_wifi_ssid);
        wifi_retry_num = 0;

        // Enable NAT routing for guest clients
        enable_nat_routing();

        // Initialize SNTP time sync
        esp_sntp_set_time_sync_notification_cb(time_sync_notification_cb);
        initialize_sntp();

        // Start SNTP poll task
        xTaskCreate(sntp_poll_task, "sntp_poll", 4096, NULL, 5, NULL);

        // Note: Slow blink will be set after time sync completes (in callback)
        ESP_LOGI(TAG, "Waiting for time sync before switching to slow blink...");
    }
}

// Simple DNS server to redirect all queries to our captive portal
static void dns_server_task(void *pvParameters)
{
    char rx_buffer[512];
    int addr_family = AF_INET;
    int ip_protocol = IPPROTO_IP;

    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(53);

    int sock = socket(addr_family, SOCK_DGRAM, ip_protocol);
    if (sock < 0)
    {
        ESP_LOGE(TAG, "Unable to create DNS socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }

    int err = bind(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err < 0)
    {
        ESP_LOGE(TAG, "DNS socket unable to bind: errno %d", errno);
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "DNS Server started on port 53");

    while (1)
    {
        struct sockaddr_in source_addr;
        socklen_t socklen = sizeof(source_addr);
        int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer) - 1, 0,
                           (struct sockaddr *)&source_addr, &socklen);

        if (len < 0)
        {
            ESP_LOGE(TAG, "DNS recvfrom failed: errno %d", errno);
            break;
        }

        // Check if client is authenticated - if so, forward DNS to gateway
        uint32_t client_ip = source_addr.sin_addr.s_addr;
        if (is_client_authenticated(client_ip))
        {
            // Get gateway IP from STA interface
            esp_netif_ip_info_t ip_info;
            if (sta_netif != NULL && esp_netif_get_ip_info(sta_netif, &ip_info) == ESP_OK && ip_info.gw.addr != 0)
            {
                // Forward DNS query to gateway (router's DNS)
                struct sockaddr_in dns_server;
                dns_server.sin_family = AF_INET;
                dns_server.sin_port = htons(53);
                dns_server.sin_addr.s_addr = ip_info.gw.addr; // Use gateway IP

                // Forward the query
                int forward_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if (forward_sock >= 0)
                {
                    // Set timeout for receiving response
                    struct timeval timeout;
                    timeout.tv_sec = 2;
                    timeout.tv_usec = 0;
                    setsockopt(forward_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

                    // Send query to gateway
                    int sent = sendto(forward_sock, rx_buffer, len, 0,
                                      (struct sockaddr *)&dns_server, sizeof(dns_server));

                    if (sent > 0)
                    {
                        // Receive response from gateway
                        char forward_response[512];
                        int response_len = recvfrom(forward_sock, forward_response, sizeof(forward_response), 0, NULL, NULL);

                        if (response_len > 0)
                        {
                            // Forward response back to client
                            sendto(sock, forward_response, response_len, 0,
                                   (struct sockaddr *)&source_addr, sizeof(source_addr));
                        }
                    }
                    close(forward_sock);
                }
            }
            continue;
        }

        // Parse DNS query (simplified - just respond to all A record queries)
        if (len > 12)
        {
            // Build DNS response pointing to our AP IP (192.168.4.1)
            char response[512];
            memcpy(response, rx_buffer, len); // Copy query
            response[2] = 0x81;               // Response flags
            response[3] = 0x80;               // Standard query response, no error
            response[7] = 0x01;               // 1 answer

            // Add answer record (simplified)
            int pos = len;
            response[pos++] = 0xC0; // Pointer to domain name
            response[pos++] = 0x0C;
            response[pos++] = 0x00; // Type A
            response[pos++] = 0x01;
            response[pos++] = 0x00; // Class IN
            response[pos++] = 0x01;
            response[pos++] = 0x00; // TTL
            response[pos++] = 0x00;
            response[pos++] = 0x00;
            response[pos++] = 0x3C;
            response[pos++] = 0x00; // Data length
            response[pos++] = 0x04;
            response[pos++] = 192; // IP: 192.168.4.1
            response[pos++] = 168;
            response[pos++] = 4;
            response[pos++] = 1;

            sendto(sock, response, pos, 0, (struct sockaddr *)&source_addr, sizeof(source_addr));
        }
    }

    close(sock);
    vTaskDelete(NULL);
}

// Basic HTTP server for captive portal
static void http_server_task(void *pvParameters)
{
    char rx_buffer[1024];
    int addr_family = AF_INET;
    int ip_protocol = IPPROTO_IP;

    struct sockaddr_in dest_addr;
    // Bind to all interfaces (0.0.0.0) to be accessible from AP and STA networks
    dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(80);

    int listen_sock = socket(addr_family, SOCK_STREAM, ip_protocol);
    if (listen_sock < 0)
    {
        ESP_LOGE(TAG, "Unable to create HTTP socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    int err = bind(listen_sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err != 0)
    {
        ESP_LOGE(TAG, "HTTP socket unable to bind: errno %d", errno);
        close(listen_sock);
        vTaskDelete(NULL);
        return;
    }

    err = listen(listen_sock, 1);
    if (err != 0)
    {
        ESP_LOGE(TAG, "Error occurred during listen: errno %d", errno);
        close(listen_sock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "HTTP Server started on port 80");

    while (1)
    {
        struct sockaddr_in source_addr;
        socklen_t addr_len = sizeof(source_addr);
        int sock = accept(listen_sock, (struct sockaddr *)&source_addr, &addr_len);
        if (sock < 0)
        {
            ESP_LOGE(TAG, "Unable to accept connection: errno %d", errno);
            break;
        }

        // Receive HTTP request
        int len = recv(sock, rx_buffer, sizeof(rx_buffer) - 1, 0);
        if (len < 0)
        {
            ESP_LOGE(TAG, "recv failed: errno %d", errno);
        }
        else if (len > 0)
        {
            rx_buffer[len] = 0;
            ESP_LOGI(TAG, "HTTP Request from %s", inet_ntoa(source_addr.sin_addr));

            // Check if client is already authenticated
            uint32_t client_ip = source_addr.sin_addr.s_addr;
            bool is_authenticated = is_client_authenticated(client_ip);

            // Check request type
            bool is_post_login = (strstr(rx_buffer, "POST /login") != NULL);
            bool is_admin_page = (strstr(rx_buffer, "GET /admin") != NULL);
            bool is_admin_config = (strstr(rx_buffer, "POST /admin/configure") != NULL);
            bool is_admin_status = (strstr(rx_buffer, "GET /admin/status") != NULL);
            bool is_customer_status = (strstr(rx_buffer, "GET /status") != NULL);
            bool is_api_token = (strstr(rx_buffer, "POST /api/token") != NULL && strstr(rx_buffer, "POST /api/token/") == NULL);
            bool is_api_token_disable = (strstr(rx_buffer, "POST /api/token/disable") != NULL);
            bool is_api_token_info = (strstr(rx_buffer, "GET /api/token/info") != NULL);
            bool is_api_token_extend = (strstr(rx_buffer, "POST /api/token/extend") != NULL);
            bool is_api_tokens_list = (strstr(rx_buffer, "GET /api/tokens/list") != NULL);
            bool is_api_uptime = (strstr(rx_buffer, "GET /api/uptime") != NULL);
            bool is_api_health = (strstr(rx_buffer, "GET /api/health") != NULL);
            bool is_admin_login = (strstr(rx_buffer, "POST /admin/login") != NULL);
            bool is_admin_logout = (strstr(rx_buffer, "POST /admin/logout") != NULL);
            bool is_admin_change_pass = (strstr(rx_buffer, "POST /admin/change_password") != NULL);
            bool is_admin_regen_key = (strstr(rx_buffer, "POST /admin/regenerate_key") != NULL);
            bool is_admin_generate_token = (strstr(rx_buffer, "POST /admin/generate_token") != NULL);

            // Handle Token API endpoint
            if (is_api_token)
            {
                // This endpoint is for third-party applications
                // Must check that request comes from uplink IP (not 192.168.4.x)
                REJECT_LOCAL_AP_REQUEST(sock, source_addr);

                // Parse POST body for API key and token parameters
                char *body = strstr(rx_buffer, "\r\n\r\n");
                if (body != NULL)
                {
                    body += 4;

                    char received_key[API_KEY_LENGTH + 1] = {0};
                    uint32_t duration = 0;
                    uint32_t bandwidth_down = 0;
                    uint32_t bandwidth_up = 0;

                    // Parse: api_key=XXX&duration=XXX&bandwidth_down=XXX&bandwidth_up=XXX
                    char *key_start = strstr(body, "api_key=");
                    char *dur_start = strstr(body, "duration=");
                    char *down_start = strstr(body, "bandwidth_down=");
                    char *up_start = strstr(body, "bandwidth_up=");

                    if (key_start && dur_start)
                    {
                        // Extract API key
                        key_start += 8;
                        sscanf(key_start, "%32[^&\r\n]", received_key);

                        // Extract duration (in minutes)
                        dur_start += 9;
                        // Check for negative sign before parsing
                        if (*dur_start == '-')
                        {
                            const char *error_response =
                                "HTTP/1.1 400 Bad Request\r\n"
                                "Content-Type: application/json\r\n"
                                "Connection: close\r\n\r\n"
                                "{\"success\":false,\"error\":\"Duration cannot be negative\"}";
                            send(sock, error_response, strlen(error_response), 0);
                            close(sock);
                            continue;
                        }
                        sscanf(dur_start, "%lu", &duration);

                        // Extract bandwidth limits (optional)
                        if (down_start)
                        {
                            down_start += 15;
                            // Check for negative bandwidth
                            if (*down_start == '-')
                            {
                                const char *error_response =
                                    "HTTP/1.1 400 Bad Request\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Connection: close\r\n\r\n"
                                    "{\"success\":false,\"error\":\"Bandwidth cannot be negative\"}";
                                send(sock, error_response, strlen(error_response), 0);
                                close(sock);
                                continue;
                            }
                            sscanf(down_start, "%lu", &bandwidth_down);
                        }
                        if (up_start)
                        {
                            up_start += 13;
                            // Check for negative bandwidth
                            if (*up_start == '-')
                            {
                                const char *error_response =
                                    "HTTP/1.1 400 Bad Request\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Connection: close\r\n\r\n"
                                    "{\"success\":false,\"error\":\"Bandwidth cannot be negative\"}";
                                send(sock, error_response, strlen(error_response), 0);
                                close(sock);
                                continue;
                            }
                            sscanf(up_start, "%lu", &bandwidth_up);
                        }

                        // Validate API key
                        if (strcmp(received_key, api_key) == 0)
                        {
                            // Create token with parameters
                            char new_token[TOKEN_LENGTH + 1];
                            esp_err_t err = create_new_token_with_params(new_token, duration,
                                                                         bandwidth_down, bandwidth_up);

                            if (err == ESP_OK)
                            {
                                char response[512];
                                snprintf(response, sizeof(response),
                                         "HTTP/1.1 200 OK\r\n"
                                         "Content-Type: application/json\r\n"
                                         "Connection: close\r\n\r\n"
                                         "{\"success\":true,\"token\":\"%s\",\"duration_minutes\":%lu,"
                                         "\"bandwidth_down_mb\":%lu,\"bandwidth_up_mb\":%lu}",
                                         new_token, duration, bandwidth_down, bandwidth_up);
                                send(sock, response, strlen(response), 0);
                                ESP_LOGI(TAG, "API: Created token %s via API", new_token);
                            }
                            else if (err == ESP_ERR_INVALID_STATE)
                            {
                                const char *error_response =
                                    "HTTP/1.1 503 Service Unavailable\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Connection: close\r\n\r\n"
                                    "{\"success\":false,\"error\":\"Time not synchronized. Please wait for time sync.\"}";
                                send(sock, error_response, strlen(error_response), 0);
                                ESP_LOGW(TAG, "API: Token creation denied - time not synced");
                            }
                            else
                            {
                                const char *error_response =
                                    "HTTP/1.1 400 Bad Request\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Connection: close\r\n\r\n"
                                    "{\"success\":false,\"error\":\"Invalid parameters or token limit reached\"}";
                                send(sock, error_response, strlen(error_response), 0);
                            }
                        }
                        else
                        {
                            send(sock, HTTP_401_INVALID_API_KEY, strlen(HTTP_401_INVALID_API_KEY), 0);
                            char client_ip_str[16];
                            inet_ntop(AF_INET, &source_addr.sin_addr, client_ip_str, sizeof(client_ip_str));
                            ESP_LOGW(TAG, "API: Invalid API key attempt from %s", client_ip_str);
                        }
                    }
                    else
                    {
                        const char *error_response =
                            "HTTP/1.1 400 Bad Request\r\n"
                            "Content-Type: application/json\r\n"
                            "Connection: close\r\n\r\n"
                            "{\"success\":false,\"error\":\"Missing required parameters\"}";
                        send(sock, error_response, strlen(error_response), 0);
                    }
                }
                close(sock);
                continue;
            }

            // Handle Token Disable API endpoint
            if (is_api_token_disable)
            {
                REJECT_LOCAL_AP_REQUEST(sock, source_addr);

                char *body = strstr(rx_buffer, "\r\n\r\n");
                if (body != NULL)
                {
                    body += 4;
                    char received_key[API_KEY_LENGTH + 1] = {0};
                    char token_to_disable[TOKEN_LENGTH + 1] = {0};

                    // Parse: api_key=XXX&token=XXX
                    char *key_start = strstr(body, "api_key=");
                    char *token_start = strstr(body, "token=");

                    if (key_start && token_start)
                    {
                        key_start += 8;
                        sscanf(key_start, "%32[^&\r\n]", received_key);

                        token_start += 6;
                        sscanf(token_start, "%8[^&\r\n]", token_to_disable);

                        // Validate API key
                        if (strcmp(received_key, api_key) == 0)
                        {
                            // Find and disable token
                            bool found = false;
                            for (int i = 0; i < token_count; i++)
                            {
                                if (active_tokens[i].active &&
                                    strcmp(active_tokens[i].token, token_to_disable) == 0)
                                {
                                    active_tokens[i].active = false;

                                    // Remove from NVS
                                    nvs_handle_t nvs_handle;
                                    if (nvs_open("tokens", NVS_READWRITE, &nvs_handle) == ESP_OK)
                                    {
                                        esp_err_t erase_err = nvs_erase_key(nvs_handle, token_to_disable);
                                        if (erase_err != ESP_OK)
                                        {
                                            ESP_LOGE(TAG, "Failed to erase token %s from NVS: %s (0x%x)",
                                                     token_to_disable, esp_err_to_name(erase_err), erase_err);
                                        }
                                        esp_err_t commit_err = nvs_commit(nvs_handle);
                                        if (commit_err != ESP_OK)
                                        {
                                            ESP_LOGE(TAG, "Failed to commit NVS after erasing token %s: %s (0x%x)",
                                                     token_to_disable, esp_err_to_name(commit_err), commit_err);
                                        }
                                        nvs_close(nvs_handle);
                                        ESP_LOGI(TAG, "Erased token %s from NVS (erase=%s, commit=%s)",
                                                 token_to_disable, esp_err_to_name(erase_err), esp_err_to_name(commit_err));
                                    }
                                    else
                                    {
                                        ESP_LOGE(TAG, "Failed to open NVS for erasing token %s", token_to_disable);
                                    }

                                    // Compact array immediately by shifting remaining tokens
                                    for (int j = i; j < token_count - 1; j++)
                                    {
                                        active_tokens[j] = active_tokens[j + 1];
                                    }
                                    token_count--;
                                    found = true;

                                    const char *success_response =
                                        "HTTP/1.1 200 OK\r\n"
                                        "Content-Type: application/json\r\n"
                                        "Connection: close\r\n\r\n"
                                        "{\"success\":true,\"message\":\"Token disabled successfully\"}";
                                    send(sock, success_response, strlen(success_response), 0);
                                    ESP_LOGI(TAG, "API: Token %s disabled via API (count now: %d)",
                                             token_to_disable, token_count);
                                    break;
                                }
                            }

                            if (!found)
                            {
                                const char *not_found_response =
                                    "HTTP/1.1 404 Not Found\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Connection: close\r\n\r\n"
                                    "{\"success\":false,\"error\":\"Token not found or already disabled\",\"error_code\":\"TOKEN_NOT_FOUND\"}";
                                send(sock, not_found_response, strlen(not_found_response), 0);
                            }
                        }
                        else
                        {
                            send(sock, HTTP_401_INVALID_API_KEY, strlen(HTTP_401_INVALID_API_KEY), 0);
                        }
                    }
                    else
                    {
                        const char *error_response =
                            "HTTP/1.1 400 Bad Request\r\n"
                            "Content-Type: application/json\r\n"
                            "Connection: close\r\n\r\n"
                            "{\"success\":false,\"error\":\"Missing required parameters (api_key, token)\"}";
                        send(sock, error_response, strlen(error_response), 0);
                    }
                }
                close(sock);
                continue;
            }

            // Handle Token Info API endpoint
            if (is_api_token_info)
            {
                REJECT_LOCAL_AP_REQUEST(sock, source_addr);

                // Parse query string: /api/token/info?api_key=XXX&token=XXX
                char received_key[API_KEY_LENGTH + 1] = {0};
                char token_to_query[TOKEN_LENGTH + 1] = {0};

                char *query_start = strstr(rx_buffer, "GET /api/token/info?");
                if (query_start)
                {
                    query_start += 20; // skip "GET /api/token/info?"
                    char *key_start = strstr(query_start, "api_key=");
                    char *token_start = strstr(query_start, "token=");

                    if (key_start && token_start)
                    {
                        key_start += 8;
                        sscanf(key_start, "%32[^&\r\n ]", received_key);

                        token_start += 6;
                        sscanf(token_start, "%8[^&\r\n ]", token_to_query);

                        // Validate API key
                        if (strcmp(received_key, api_key) == 0)
                        {
                            // Find token (only search through active token_count, not MAX_TOKENS)
                            bool found = false;
                            for (int i = 0; i < token_count; i++)
                            {
                                if (active_tokens[i].active &&
                                    strcmp(active_tokens[i].token, token_to_query) == 0)
                                {
                                    found = true;
                                    time_t now = time(NULL);
                                    // For unused tokens, expires_at is creation + duration
                                    // For used tokens, expires_at is first_use + duration
                                    time_t expires_at = active_tokens[i].first_use > 0
                                                            ? active_tokens[i].first_use + (active_tokens[i].duration_minutes * 60)
                                                            : active_tokens[i].created + (active_tokens[i].duration_minutes * 60);
                                    bool is_expired = (active_tokens[i].first_use > 0 && now > expires_at);
                                    bool is_used = (active_tokens[i].first_use > 0);
                                    int64_t remaining_seconds = is_used && !is_expired
                                                                    ? (expires_at - now)
                                                                    : 0;

                                    char response[1024];
                                    snprintf(response, sizeof(response),
                                             "HTTP/1.1 200 OK\r\n"
                                             "Content-Type: application/json\r\n"
                                             "Connection: close\r\n\r\n"
                                             "{\"success\":true,\"token\":\"%s\","
                                             "\"status\":\"%s\","
                                             "\"created\":%lld,"
                                             "\"first_use\":%lld,"
                                             "\"duration_minutes\":%lu,"
                                             "\"expires_at\":%lld,"
                                             "\"remaining_seconds\":%lld,"
                                             "\"bandwidth_down_mb\":%lu,"
                                             "\"bandwidth_up_mb\":%lu,"
                                             "\"bandwidth_used_down_mb\":%lu,"
                                             "\"bandwidth_used_up_mb\":%lu,"
                                             "\"usage_count\":%lu,"
                                             "\"device_count\":%u,"
                                             "\"max_devices\":%d}",
                                             active_tokens[i].token,
                                             is_expired ? "expired" : (is_used ? "active" : "unused"),
                                             (long long)active_tokens[i].created,
                                             (long long)active_tokens[i].first_use,
                                             active_tokens[i].duration_minutes,
                                             (long long)expires_at,
                                             remaining_seconds,
                                             active_tokens[i].bandwidth_down_mb,
                                             active_tokens[i].bandwidth_up_mb,
                                             active_tokens[i].bandwidth_used_down,
                                             active_tokens[i].bandwidth_used_up,
                                             active_tokens[i].usage_count,
                                             active_tokens[i].device_count,
                                             MAX_DEVICES_PER_TOKEN);
                                    send(sock, response, strlen(response), 0);
                                    break;
                                }
                            }

                            if (!found)
                            {
                                const char *not_found_response =
                                    "HTTP/1.1 404 Not Found\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Connection: close\r\n\r\n"
                                    "{\"success\":false,\"error\":\"Token not found\",\"error_code\":\"TOKEN_NOT_FOUND\"}";
                                send(sock, not_found_response, strlen(not_found_response), 0);
                            }
                        }
                        else
                        {
                            send(sock, HTTP_401_INVALID_API_KEY, strlen(HTTP_401_INVALID_API_KEY), 0);
                        }
                    }
                    else
                    {
                        const char *error_response =
                            "HTTP/1.1 400 Bad Request\r\n"
                            "Content-Type: application/json\r\n"
                            "Connection: close\r\n\r\n"
                            "{\"success\":false,\"error\":\"Missing required parameters (api_key, token)\"}";
                        send(sock, error_response, strlen(error_response), 0);
                    }
                }
                close(sock);
                continue;
            }

            // Handle Token Extend API endpoint
            if (is_api_token_extend)
            {
                REJECT_LOCAL_AP_REQUEST(sock, source_addr);

                char *body = strstr(rx_buffer, "\r\n\r\n");
                if (body != NULL)
                {
                    body += 4;
                    char received_key[API_KEY_LENGTH + 1] = {0};
                    char token_to_extend[TOKEN_LENGTH + 1] = {0};

                    // Parse: api_key=XXX&token=XXX
                    char *key_start = strstr(body, "api_key=");
                    char *token_start = strstr(body, "token=");

                    if (key_start && token_start)
                    {
                        key_start += 8;
                        sscanf(key_start, "%32[^&\r\n]", received_key);

                        token_start += 6;
                        sscanf(token_start, "%8[^&\r\n]", token_to_extend);

                        // Validate API key
                        if (strcmp(received_key, api_key) == 0)
                        {
                            // Find token
                            bool found = false;
                            for (int i = 0; i < MAX_TOKENS; i++)
                            {
                                if (active_tokens[i].active &&
                                    strcmp(active_tokens[i].token, token_to_extend) == 0)
                                {
                                    found = true;

                                    // Reset data usage counters
                                    active_tokens[i].bandwidth_used_down = 0;
                                    active_tokens[i].bandwidth_used_up = 0;

                                    // Reset time - set first_use to now to restart the duration
                                    active_tokens[i].first_use = time(NULL);

                                    // Reset usage count
                                    active_tokens[i].usage_count = 0;

                                    save_token_to_nvs(token_to_extend, &active_tokens[i]); // Persist to NVS

                                    time_t new_expires = active_tokens[i].first_use +
                                                         (active_tokens[i].duration_minutes * 60);

                                    char response[512];
                                    snprintf(response, sizeof(response),
                                             "HTTP/1.1 200 OK\r\n"
                                             "Content-Type: application/json\r\n"
                                             "Connection: close\r\n\r\n"
                                             "{\"success\":true,"
                                             "\"message\":\"Token extended successfully\","
                                             "\"token\":\"%s\","
                                             "\"duration_minutes\":%lu,"
                                             "\"new_duration_minutes\":%lu,"
                                             "\"new_expires_at\":%lld,"
                                             "\"bandwidth_down_mb\":%lu,"
                                             "\"bandwidth_up_mb\":%lu}",
                                             active_tokens[i].token,
                                             active_tokens[i].duration_minutes,
                                             active_tokens[i].duration_minutes,
                                             (long long)new_expires,
                                             active_tokens[i].bandwidth_down_mb,
                                             active_tokens[i].bandwidth_up_mb);
                                    send(sock, response, strlen(response), 0);
                                    ESP_LOGI(TAG, "API: Token %s extended via API", token_to_extend);
                                    break;
                                }
                            }

                            if (!found)
                            {
                                const char *not_found_response =
                                    "HTTP/1.1 404 Not Found\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Connection: close\r\n\r\n"
                                    "{\"success\":false,\"error\":\"Token not found or has been disabled\",\"error_code\":\"TOKEN_NOT_FOUND\"}";
                                send(sock, not_found_response, strlen(not_found_response), 0);
                            }
                        }
                        else
                        {
                            send(sock, HTTP_401_INVALID_API_KEY, strlen(HTTP_401_INVALID_API_KEY), 0);
                        }
                    }
                    else
                    {
                        const char *error_response =
                            "HTTP/1.1 400 Bad Request\r\n"
                            "Content-Type: application/json\r\n"
                            "Connection: close\r\n\r\n"
                            "{\"success\":false,\"error\":\"Missing required parameters (api_key, token)\"}";
                        send(sock, error_response, strlen(error_response), 0);
                    }
                }
                close(sock);
                continue;
            }

            // Handle Uptime API endpoint
            if (is_api_uptime)
            {
                REJECT_LOCAL_AP_REQUEST(sock, source_addr);

                // Calculate uptime using esp_timer
                int64_t uptime_us = esp_timer_get_time();
                int64_t uptime_sec = uptime_us / 1000000;

                char response[512];
                snprintf(response, sizeof(response),
                         "HTTP/1.1 200 OK\r\n" HTTP_HEADER_JSON
                         "{\"success\":true,\"uptime_seconds\":%lld,"
                         "\"uptime_microseconds\":%lld}",
                         uptime_sec, uptime_us);
                send(sock, response, strlen(response), 0);
                close(sock);
                continue;
            }

            // Handle Health Check API endpoint
            if (is_api_health)
            {
                REJECT_LOCAL_AP_REQUEST(sock, source_addr);

                // Gather health metrics
                int64_t uptime_us = esp_timer_get_time();
                int64_t uptime_sec = uptime_us / 1000000;
                uint32_t free_heap = esp_get_free_heap_size();
                time_t now = time(NULL);

                // Count active tokens
                int active_count = 0;
                for (int i = 0; i < token_count; i++)
                {
                    if (active_tokens[i].active)
                        active_count++;
                }

                char response[1024];
                snprintf(response, sizeof(response),
                         "HTTP/1.1 200 OK\r\n" HTTP_HEADER_JSON
                         "{\"success\":true,\"status\":\"healthy\","
                         "\"uptime_seconds\":%lld,"
                         "\"time_synced\":%s,"
                         "\"last_time_sync\":%lld,"
                         "\"current_time\":%lld,"
                         "\"active_tokens\":%d,"
                         "\"max_tokens\":%d,"
                         "\"free_heap_bytes\":%lu}",
                         uptime_sec,
                         time_synced ? "true" : "false",
                         (long long)time_sync_timestamp,
                         (long long)now,
                         active_count,
                         MAX_TOKENS,
                         free_heap);
                send(sock, response, strlen(response), 0);
                close(sock);
                continue;
            }

            // Handle Tokens List API endpoint
            if (is_api_tokens_list)
            {
                REJECT_LOCAL_AP_REQUEST(sock, source_addr);

                // Parse query string: /api/tokens/list?api_key=XXX
                char *query_start = strstr(rx_buffer, "GET /api/tokens/list?");
                if (query_start != NULL)
                {
                    query_start += 21; // skip "GET /api/tokens/list?"
                    char received_key[API_KEY_LENGTH + 1] = {0};

                    char *key_start = strstr(query_start, "api_key=");
                    if (key_start)
                    {
                        key_start += 8;
                        sscanf(key_start, "%32[^& \r\n]", received_key);

                        // Validate API key
                        if (strcmp(received_key, api_key) == 0)
                        {
                            // Build JSON response with all tokens
                            char *response = malloc(8192); // Allocate larger buffer for token list
                            if (response == NULL)
                            {
                                const char *error_response =
                                    "HTTP/1.1 500 Internal Server Error\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Connection: close\r\n\r\n"
                                    "{\"success\":false,\"error\":\"Memory allocation failed\"}";
                                send(sock, error_response, strlen(error_response), 0);
                                close(sock);
                                continue;
                            }

                            int offset = snprintf(response, 8192,
                                                  "HTTP/1.1 200 OK\r\n" HTTP_HEADER_JSON
                                                  "{\"success\":true,\"count\":%d,\"tokens\":[",
                                                  token_count);

                            time_t now = time(NULL);
                            for (int i = 0; i < token_count; i++)
                            {
                                if (active_tokens[i].active)
                                {
                                    time_t expires_at = active_tokens[i].first_use > 0
                                                            ? active_tokens[i].first_use + (active_tokens[i].duration_minutes * 60)
                                                            : now + (active_tokens[i].duration_minutes * 60);

                                    int remaining_sec = (int)difftime(expires_at, now);
                                    const char *status = (active_tokens[i].first_use == 0) ? "unused"
                                                         : (remaining_sec > 0)             ? "active"
                                                                                           : "expired";

                                    offset += snprintf(response + offset, 8192 - offset,
                                                       "%s{\"token\":\"%s\","
                                                       "\"status\":\"%s\","
                                                       "\"duration_minutes\":%lu,"
                                                       "\"first_use\":%lld,"
                                                       "\"expires_at\":%lld,"
                                                       "\"remaining_seconds\":%d,"
                                                       "\"bandwidth_down_mb\":%lu,"
                                                       "\"bandwidth_up_mb\":%lu,"
                                                       "\"bandwidth_used_down\":%lu,"
                                                       "\"bandwidth_used_up\":%lu,"
                                                       "\"usage_count\":%lu}",
                                                       (i > 0) ? "," : "",
                                                       active_tokens[i].token,
                                                       status,
                                                       active_tokens[i].duration_minutes,
                                                       (long long)active_tokens[i].first_use,
                                                       (long long)expires_at,
                                                       remaining_sec > 0 ? remaining_sec : 0,
                                                       active_tokens[i].bandwidth_down_mb,
                                                       active_tokens[i].bandwidth_up_mb,
                                                       active_tokens[i].bandwidth_used_down,
                                                       active_tokens[i].bandwidth_used_up,
                                                       active_tokens[i].usage_count);

                                    if (offset >= 7800)
                                    { // Leave room for closing
                                        break;
                                    }
                                }
                            }

                            snprintf(response + offset, 8192 - offset, "]}");
                            send(sock, response, strlen(response), 0);
                            free(response);
                            ESP_LOGI(TAG, "API: Listed %d tokens via API", token_count);
                        }
                        else
                        {
                            send(sock, HTTP_401_INVALID_API_KEY, strlen(HTTP_401_INVALID_API_KEY), 0);
                        }
                    }
                    else
                    {
                        const char *error_response =
                            "HTTP/1.1 400 Bad Request\r\n"
                            "Content-Type: application/json\r\n"
                            "Connection: close\r\n\r\n"
                            "{\"success\":false,\"error\":\"Missing required parameter: api_key\"}";
                        send(sock, error_response, strlen(error_response), 0);
                    }
                }
                close(sock);
                continue;
            }

            // Handle invalid API endpoints - return 404 for unmatched /api/* routes
            if (strstr(rx_buffer, "GET /api/") != NULL || strstr(rx_buffer, "POST /api/") != NULL)
            {
                // Check if it's not one of our known endpoints
                bool is_known_api = is_api_token || is_api_token_disable || is_api_token_info ||
                                    is_api_token_extend || is_api_tokens_list || is_api_uptime || is_api_health;

                if (!is_known_api)
                {
                    const char *not_found_response =
                        "HTTP/1.1 404 Not Found\r\n"
                        "Content-Type: application/json\r\n"
                        "Connection: close\r\n\r\n"
                        "{\"success\":false,\"error\":\"API endpoint not found\",\"error_code\":\"NOT_FOUND\"}";
                    send(sock, not_found_response, strlen(not_found_response), 0);
                    close(sock);
                    continue;
                }
            }

            // Handle admin login
            if (is_admin_login)
            {
                char *body = strstr(rx_buffer, "\r\n\r\n");
                if (body != NULL)
                {
                    body += 4;
                    char password[64] = {0};
                    char *pass_start = strstr(body, "password=");

                    if (pass_start)
                    {
                        pass_start += 9;
                        sscanf(pass_start, "%63[^&\r\n]", password);

                        if (strcmp(password, admin_password) == 0)
                        {
                            admin_logged_in = true;
                            update_admin_activity();

                            const char *success =
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: application/json\r\n"
                                "Connection: close\r\n\r\n"
                                "{\"success\":true}";
                            send(sock, success, strlen(success), 0);
                            ESP_LOGI(TAG, "Admin logged in from %s", inet_ntoa(source_addr.sin_addr));
                        }
                        else
                        {
                            const char *error =
                                "HTTP/1.1 401 Unauthorized\r\n"
                                "Content-Type: application/json\r\n"
                                "Connection: close\r\n\r\n"
                                "{\"success\":false,\"error\":\"Invalid password\"}";
                            send(sock, error, strlen(error), 0);
                        }
                    }
                }
                close(sock);
                continue;
            }

            // Handle admin logout
            if (is_admin_logout)
            {
                admin_logged_in = false;
                const char *response =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    "Connection: close\r\n\r\n"
                    "{\"success\":true}";
                send(sock, response, strlen(response), 0);
                close(sock);
                continue;
            }

            // Handle admin password change
            if (is_admin_change_pass)
            {
                if (!is_admin_session_valid())
                {
                    const char *error =
                        "HTTP/1.1 401 Unauthorized\r\n"
                        "Content-Type: application/json\r\n"
                        "Connection: close\r\n\r\n"
                        "{\"success\":false,\"error\":\"Session expired\"}";
                    send(sock, error, strlen(error), 0);
                    close(sock);
                    continue;
                }

                char *body = strstr(rx_buffer, "\r\n\r\n");
                if (body != NULL)
                {
                    body += 4;
                    char old_pass[64] = {0};
                    char new_pass[64] = {0};

                    char *old_start = strstr(body, "old_password=");
                    char *new_start = strstr(body, "new_password=");

                    if (old_start && new_start)
                    {
                        old_start += 13;
                        sscanf(old_start, "%63[^&\r\n]", old_pass);

                        new_start += 13;
                        sscanf(new_start, "%63[^&\r\n]", new_pass);

                        esp_err_t err = change_admin_password(old_pass, new_pass);
                        if (err == ESP_OK)
                        {
                            update_admin_activity();
                            const char *success =
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: application/json\r\n"
                                "Connection: close\r\n\r\n"
                                "{\"success\":true}";
                            send(sock, success, strlen(success), 0);
                        }
                        else
                        {
                            const char *error =
                                "HTTP/1.1 400 Bad Request\r\n"
                                "Content-Type: application/json\r\n"
                                "Connection: close\r\n\r\n"
                                "{\"success\":false,\"error\":\"Invalid old password or new password too short\"}";
                            send(sock, error, strlen(error), 0);
                        }
                    }
                }
                close(sock);
                continue;
            }

            // Handle API key regeneration
            if (is_admin_regen_key)
            {
                if (!is_admin_session_valid())
                {
                    const char *error =
                        "HTTP/1.1 401 Unauthorized\r\n"
                        "Content-Type: application/json\r\n"
                        "Connection: close\r\n\r\n"
                        "{\"success\":false,\"error\":\"Session expired\"}";
                    send(sock, error, strlen(error), 0);
                    close(sock);
                    continue;
                }

                esp_err_t err = regenerate_api_key();
                if (err == ESP_OK)
                {
                    update_admin_activity();
                    char response[512];
                    snprintf(response, sizeof(response),
                             "HTTP/1.1 200 OK\r\n"
                             "Content-Type: application/json\r\n"
                             "Connection: close\r\n\r\n"
                             "{\"success\":true,\"api_key\":\"%s\"}",
                             api_key);
                    send(sock, response, strlen(response), 0);
                }
                else
                {
                    const char *error =
                        "HTTP/1.1 500 Internal Server Error\r\n"
                        "Content-Type: application/json\r\n"
                        "Connection: close\r\n\r\n"
                        "{\"success\":false,\"error\":\"Failed to regenerate key\"}";
                    send(sock, error, strlen(error), 0);
                }
                close(sock);
                continue;
            }

            // Handle admin token generation
            if (is_admin_generate_token)
            {
                if (!is_admin_session_valid())
                {
                    const char *error =
                        "HTTP/1.1 401 Unauthorized\r\n"
                        "Content-Type: application/json\r\n"
                        "Connection: close\r\n\r\n"
                        "{\"success\":false,\"error\":\"Session expired\"}";
                    send(sock, error, strlen(error), 0);
                    close(sock);
                    continue;
                }

                char *body = strstr(rx_buffer, "\r\n\r\n");
                if (body != NULL)
                {
                    body += 4;
                    uint32_t duration = 0;

                    char *dur_start = strstr(body, "duration=");
                    if (dur_start)
                    {
                        dur_start += 9;
                        sscanf(dur_start, "%lu", &duration);

                        char new_token[TOKEN_LENGTH + 1];
                        esp_err_t err = create_new_token_with_params(new_token, duration, 0, 0);

                        if (err == ESP_OK)
                        {
                            update_admin_activity();
                            char response[256];
                            snprintf(response, sizeof(response),
                                     "HTTP/1.1 200 OK\r\n"
                                     "Content-Type: application/json\r\n"
                                     "Connection: close\r\n\r\n"
                                     "{\"success\":true,\"token\":\"%s\"}",
                                     new_token);
                            send(sock, response, strlen(response), 0);
                        }
                        else if (err == ESP_ERR_INVALID_STATE)
                        {
                            const char *error =
                                "HTTP/1.1 503 Service Unavailable\r\n"
                                "Content-Type: application/json\r\n"
                                "Connection: close\r\n\r\n"
                                "{\"success\":false,\"error\":\"Time not synchronized. Please connect to internet.\"}";
                            send(sock, error, strlen(error), 0);
                            ESP_LOGW(TAG, "Admin: Token creation denied - time not synced");
                        }
                        else
                        {
                            const char *error =
                                "HTTP/1.1 400 Bad Request\r\n"
                                "Content-Type: application/json\r\n"
                                "Connection: close\r\n\r\n"
                                "{\"success\":false,\"error\":\"Invalid duration or token limit reached\"}";
                            send(sock, error, strlen(error), 0);
                        }
                    }
                }
                close(sock);
                continue;
            }

            // Handle admin configuration
            if (is_admin_config)
            {
                // Extract admin password, SSID, and password from POST data
                char *body = strstr(rx_buffer, "\r\n\r\n");
                if (body != NULL)
                {
                    body += 4;

                    // Debug: Log the raw POST body
                    ESP_LOGI(TAG, "Raw POST body: '%s'", body);

                    char admin_pass[64] = {0};
                    char new_ssid[32] = {0};
                    char new_pass[64] = {0};
                    bool use_static = false;
                    char new_static_ip[16] = {0};
                    char new_static_gw[16] = {0};
                    char new_static_nm[16] = {0};
                    char new_static_dns[16] = {0};

                    // Parse admin_password=XXX&ssid=XXX&password=XXX&use_static=XXX&static_ip=...
                    char *admin_pass_start = strstr(body, "admin_password=");
                    char *ssid_start = strstr(body, "&ssid=");
                    char *pass_start = NULL;
                    char *use_static_start = strstr(body, "&use_static=");
                    char *static_ip_start = strstr(body, "&static_ip=");
                    char *static_gw_start = strstr(body, "&static_gw=");
                    char *static_nm_start = strstr(body, "&static_nm=");
                    char *static_dns_start = strstr(body, "&static_dns=");

                    // Find password= AFTER ssid= to avoid matching admin_password=
                    if (ssid_start)
                    {
                        pass_start = strstr(ssid_start, "&password=");
                    }

                    if (admin_pass_start && ssid_start && pass_start)
                    {
                        // Extract admin password
                        admin_pass_start += 15; // skip "admin_password="
                        int i = 0;
                        while (i < 63 && admin_pass_start[i] && admin_pass_start[i] != '&' && admin_pass_start[i] != '\r' && admin_pass_start[i] != '\n')
                        {
                            admin_pass[i] = admin_pass_start[i];
                            i++;
                        }
                        admin_pass[i] = '\0'; // Ensure null termination

                        // Extract SSID
                        ssid_start += 6; // skip "&ssid="
                        i = 0;
                        while (i < 31 && ssid_start[i] && ssid_start[i] != '&' && ssid_start[i] != '\r' && ssid_start[i] != '\n')
                        {
                            // URL decode space as +
                            new_ssid[i] = (ssid_start[i] == '+') ? ' ' : ssid_start[i];
                            i++;
                        }
                        new_ssid[i] = '\0'; // Ensure null termination

                        // Extract WiFi password
                        pass_start += 10; // skip "&password="
                        i = 0;
                        while (i < 63 && pass_start[i] && pass_start[i] != '&' && pass_start[i] != '\r' && pass_start[i] != '\n')
                        {
                            new_pass[i] = pass_start[i];
                            i++;
                        }
                        new_pass[i] = '\0'; // Ensure null termination

                        // Extract static IP configuration
                        if (use_static_start)
                        {
                            use_static_start += 12; // skip "&use_static="
                            use_static = (strncmp(use_static_start, "true", 4) == 0);
                        }

                        if (use_static && static_ip_start && static_gw_start && static_nm_start && static_dns_start)
                        {
                            // Extract static IP
                            static_ip_start += 11; // skip "&static_ip="
                            sscanf(static_ip_start, "%15[^&\r\n]", new_static_ip);

                            // Extract gateway
                            static_gw_start += 11; // skip "&static_gw="
                            sscanf(static_gw_start, "%15[^&\r\n]", new_static_gw);

                            // Extract netmask
                            static_nm_start += 11; // skip "&static_nm="
                            sscanf(static_nm_start, "%15[^&\r\n]", new_static_nm);

                            // Extract DNS
                            static_dns_start += 12; // skip "&static_dns="
                            sscanf(static_dns_start, "%15[^&\r\n]", new_static_dns);
                        }

                        // Debug logging
                        ESP_LOGI(TAG, "Admin config received - SSID: '%s', Password length: %d", new_ssid, strlen(new_pass));
                        ESP_LOGI(TAG, "Static IP mode: %s", use_static ? "enabled" : "disabled");

                        // Verify admin password
                        if (strcmp(admin_pass, admin_password) == 0)
                        {
                            update_admin_activity(); // Update session

                            // Save WiFi credentials and static IP config
                            esp_err_t err = save_wifi_credentials(new_ssid, new_pass);
                            if (err == ESP_OK && use_static)
                            {
                                err = save_static_ip_config(use_static, new_static_ip,
                                                            new_static_gw, new_static_nm, new_static_dns);
                            }
                            else if (err == ESP_OK && !use_static)
                            {
                                // Save DHCP mode
                                err = save_static_ip_config(false, "", "", "", "");
                            }

                            if (err == ESP_OK)
                            {
                                reconnect_wifi();

                                const char *success_response =
                                    "HTTP/1.1 200 OK\r\n"
                                    "Content-Type: text/html\r\n"
                                    "Connection: close\r\n"
                                    "\r\n"
                                    "<!DOCTYPE html><html><head><title>WiFi Updated</title>"
                                    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                                    "<style>body{font-family:Arial;margin:40px;background:#f0f0f0;text-align:center}"
                                    ".box{background:white;padding:30px;border-radius:10px;max-width:500px;margin:0 auto;box-shadow:0 2px 10px rgba(0,0,0,0.1)}"
                                    "h1{color:#28a745}p{color:#666}a{color:#007bff;text-decoration:none}</style></head>"
                                    "<body><div class='box'><h1>✓ WiFi Configuration Updated</h1>"
                                    "<p>Connecting to: <strong>%s</strong></p>"
                                    "<p>The device is now attempting to connect to the new network.</p>"
                                    "<p><a href='/admin'>← Back to Admin</a></p></div></body></html>";

                                char response[2048];
                                snprintf(response, sizeof(response), success_response, new_ssid);
                                send(sock, response, strlen(response), 0);
                            }
                            else
                            {
                                const char *error_response =
                                    "HTTP/1.1 500 Internal Server Error\r\n"
                                    "Content-Type: text/html\r\n"
                                    "Connection: close\r\n\r\n"
                                    "<!DOCTYPE html><html><head><title>Error</title></head>"
                                    "<body><h1>Error saving configuration</h1><a href='/admin'>Try Again</a></body></html>";
                                send(sock, error_response, strlen(error_response), 0);
                            }
                        }
                        else
                        {
                            const char *auth_error =
                                "HTTP/1.1 401 Unauthorized\r\n"
                                "Content-Type: text/html\r\n"
                                "Connection: close\r\n\r\n"
                                "<!DOCTYPE html><html><head><title>Access Denied</title></head>"
                                "<body><h1>Invalid admin password</h1><a href='/admin'>Try Again</a></body></html>";
                            send(sock, auth_error, strlen(auth_error), 0);
                        }
                    }
                }
                close(sock);
                continue;
            }

            // Handle admin status API
            if (is_admin_status)
            {
                wifi_ap_record_t ap_info;
                esp_err_t err = esp_wifi_sta_get_ap_info(&ap_info);
                bool sta_connected = (err == ESP_OK);

                // Get mesh information
                bool is_root = esp_mesh_is_root();
                int routing_size = esp_mesh_get_routing_table_size();
                const char *mesh_role = is_root ? "ROOT" : "CHILD";

                char status_json[768];
                snprintf(status_json, sizeof(status_json),
                         "HTTP/1.1 200 OK\r\n"
                         "Content-Type: application/json\r\n"
                         "Connection: close\r\n\r\n"
                         "{\"sta_connected\":%s,\"ssid\":\"%s\",\"rssi\":%d,\"current_ssid\":\"%s\","
                         "\"mesh_connected\":%s,\"mesh_role\":\"%s\",\"mesh_layer\":%d,\"mesh_routing_size\":%d}",
                         sta_connected ? "true" : "false",
                         sta_connected ? (char *)ap_info.ssid : "Not connected",
                         sta_connected ? ap_info.rssi : 0,
                         current_wifi_ssid,
                         mesh_connected ? "true" : "false",
                         mesh_role,
                         mesh_layer,
                         routing_size);
                send(sock, status_json, strlen(status_json), 0);
                close(sock);
                continue;
            }

            // Handle admin page
            if (is_admin_page)
            {
                // Check if admin is logged in
                if (!is_admin_session_valid())
                {
                    // Show login page
                    const char *login_page =
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/html; charset=UTF-8\r\n"
                        "Connection: close\r\n\r\n"
                        "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Admin Login</title>"
                        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                        "<style>*{margin:0;padding:0;box-sizing:border-box}"
                        "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;background:linear-gradient(135deg,#667eea 0%%,#764ba2 100%%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}"
                        ".login-box{background:white;padding:40px;border-radius:15px;box-shadow:0 10px 40px rgba(0,0,0,0.2);max-width:400px;width:100%%}"
                        "h1{color:#333;margin-bottom:10px;font-size:28px}p{color:#666;margin-bottom:30px}"
                        "input{width:100%%;padding:12px;border:2px solid #e1e8ed;border-radius:8px;margin-bottom:15px;font-size:16px}"
                        "input:focus{outline:none;border-color:#667eea}button{width:100%%;padding:14px;background:#667eea;color:white;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;transition:all 0.3s}"
                        "button:hover{background:#5568d3}.error{color:#dc3545;margin-top:10px;display:none}"
                        "</style></head><body><div class='login-box'>"
                        "<h1>🔐 Admin Login</h1><p>Enter your admin password</p>"
                        "<form id='loginForm'>"
                        "<input type='password' id='password' placeholder='Admin Password' required autofocus>"
                        "<button type='submit'>Login</button>"
                        "<div class='error' id='error'>Invalid password</div>"
                        "</form></div>"
                        "<script>document.getElementById('loginForm').addEventListener('submit',function(e){"
                        "e.preventDefault();var p=document.getElementById('password').value;"
                        "fetch('/admin/login',{method:'POST',body:'password='+encodeURIComponent(p)})"
                        ".then(r=>r.json()).then(d=>{if(d.success){window.location.reload()}else{document.getElementById('error').style.display='block'}})"
                        "});</script></body></html>";
                    send(sock, login_page, strlen(login_page), 0);
                }
                else
                {
                    // Show admin dashboard
                    update_admin_activity();

                    // Get uplink IP address
                    esp_netif_ip_info_t ip_info;
                    char uplink_ip[16] = "Not connected";
                    if (esp_netif_get_ip_info(sta_netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0)
                    {
                        snprintf(uplink_ip, sizeof(uplink_ip), IPSTR, IP2STR(&ip_info.ip));
                    }

                    // Send response in parts to avoid stack overflow
                    const char *header =
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/html; charset=UTF-8\r\n"
                        "Connection: close\r\n\r\n"
                        "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Admin Dashboard</title>"
                        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                        "<style>*{margin:0;padding:0;box-sizing:border-box}"
                        "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;background:#f5f7fa;padding:20px}"
                        ".header{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;padding:30px;border-radius:15px;margin-bottom:20px;box-shadow:0 5px 20px rgba(0,0,0,0.1)}"
                        ".header h1{font-size:32px;margin-bottom:5px}.header p{opacity:0.9}"
                        ".container{max-width:1200px;margin:0 auto}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:20px;margin-bottom:20px}"
                        ".card{background:white;padding:25px;border-radius:12px;box-shadow:0 2px 10px rgba(0,0,0,0.08)}"
                        ".card h2{color:#333;margin-bottom:15px;font-size:20px;display:flex;align-items:center}"
                        ".card h2::before{content:'';display:inline-block;width:4px;height:20px;background:#667eea;margin-right:10px;border-radius:2px}"
                        "label{display:block;margin:15px 0 5px;font-weight:600;color:#555;font-size:14px}"
                        "input,select{width:100%;padding:10px;border:2px solid #e1e8ed;border-radius:8px;font-size:14px}"
                        "input:focus,select:focus{outline:none;border-color:#667eea}"
                        "button{padding:10px 20px;background:#667eea;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:600;margin-top:10px;transition:all 0.3s}"
                        "button:hover{background:#5568d3}button.secondary{background:#6c757d}button.secondary:hover{background:#5a6268}"
                        "button.danger{background:#dc3545}button.danger:hover{background:#c82333}"
                        ".info-box{background:#e7f3ff;border-left:4px solid #007bff;padding:15px;margin:15px 0;border-radius:5px}"
                        ".info-box strong{display:block;margin-bottom:5px}"
                        ".api-key{font-family:monospace;background:#f8f9fa;padding:10px;border-radius:5px;word-break:break-all;margin:10px 0}"
                        ".token-display{background:#d4edda;border-left:4px solid #28a745;padding:15px;margin:10px 0;border-radius:5px;display:none}"
                        ".token-display strong{font-size:24px;font-family:monospace;display:block;margin:10px 0}"
                        ".status-badge{display:inline-block;padding:5px 12px;border-radius:20px;font-size:12px;font-weight:600}"
                        ".status-ok{background:#d4edda;color:#155724}.status-error{background:#f8d7da;color:#721c24}"
                        ".logout-btn{position:absolute;top:30px;right:30px}"
                        ".header{position:relative}"
                        "</style></head><body><div class='container'>"
                        "<div class='header'><h1>🎛️ Admin Dashboard</h1><p>Manage your ESP32 Portal</p>"
                        "<button class='logout-btn secondary' onclick='logout()'>Logout</button></div>"
                        "<div class='grid'>";

                    send(sock, header, strlen(header), 0);

                    // API Management card with dynamic data
                    char api_card[512];
                    snprintf(api_card, sizeof(api_card),
                             "<div class='card'><h2>🔑 API Management</h2>"
                             "<p style='color:#666;margin-bottom:15px'>API key for third-party token generation</p>"
                             "<div class='api-key' id='apiKey'>%s</div>"
                             "<button onclick='regenKey()'>Regenerate API Key</button>"
                             "<div class='info-box' style='margin-top:15px'><strong>Uplink IP:</strong> %s<br>"
                             "<small>Use this IP for API requests</small></div></div>",
                             api_key, uplink_ip);
                    send(sock, api_card, strlen(api_card), 0);

                    // Token generation card
                    const char *token_card =
                        "<div class='card'><h2>🎫 Generate Token</h2>"
                        "<label>Duration:</label><select id='duration'>"
                        "<option value='30'>30 minutes</option><option value='60'>1 hour</option>"
                        "<option value='120'>2 hours</option><option value='240'>4 hours</option>"
                        "<option value='480'>8 hours</option><option value='720' selected>12 hours</option>"
                        "</select><button onclick='generateToken()'>Create Token</button>"
                        "<div class='token-display' id='tokenDisplay'>"
                        "<strong>Token Created!</strong><strong id='newToken'></strong>"
                        "<p style='margin-top:10px;color:#155724'>Share this token with guests</p></div></div>";
                    send(sock, token_card, strlen(token_card), 0);

                    // Mesh network status card
                    const char *mesh_card =
                        "<div class='card'><h2>🕸️ Mesh Network</h2>"
                        "<div id='meshStatus' class='info-box'>Loading...</div>"
                        "<p style='margin-top:10px;font-size:12px;color:#666'>"
                        "Mesh ID: " MESH_ID "<br>"
                        "Max Layers: " TOSTRING(MESH_MAX_LAYER) "<br>"
                                                                "Channel: " TOSTRING(MESH_CHANNEL) "</p></div>";
                    send(sock, mesh_card, strlen(mesh_card), 0);

                    // WiFi card with dynamic SSID and static IP options
                    char wifi_card[1536];
                    snprintf(wifi_card, sizeof(wifi_card),
                             "<div class='card'><h2>📡 WiFi Uplink</h2>"
                             "<div id='wifiStatus' class='info-box'>Loading...</div>"
                             "<form id='wifiForm'>"
                             "<label>Admin Password:</label><input type='password' id='adminPass' required>"
                             "<label>Router SSID:</label><input type='text' id='ssid' value='%s' required>"
                             "<label>Router Password:</label><input type='password' id='pass' required>"
                             "<div style='margin:15px 0;padding:10px;background:#f8f9fa;border-radius:5px'>"
                             "<label style='display:flex;align-items:center;cursor:pointer'>"
                             "<input type='checkbox' id='useStatic' %s style='margin-right:8px'> Use Static IP</label>"
                             "<div id='staticIpFields' style='display:%s;margin-top:10px'>"
                             "<label>IP Address:</label><input type='text' id='staticIp' value='%s' placeholder='192.168.1.100'>"
                             "<label>Gateway:</label><input type='text' id='staticGw' value='%s' placeholder='192.168.1.1'>"
                             "<label>Subnet Mask:</label><input type='text' id='staticNm' value='%s' placeholder='255.255.255.0'>"
                             "<label>DNS Server:</label><input type='text' id='staticDns' value='%s' placeholder='8.8.8.8'>"
                             "</div></div>"
                             "<button type='submit'>Update WiFi</button></form></div>",
                             current_wifi_ssid,
                             use_static_ip ? "checked" : "",
                             use_static_ip ? "block" : "none",
                             static_ip,
                             static_gateway,
                             static_netmask,
                             static_dns);
                    send(sock, wifi_card, strlen(wifi_card), 0);

                    // Password change card
                    const char *pass_card =
                        "<div class='card'><h2>🔐 Change Password</h2>"
                        "<form id='passForm'>"
                        "<label>Current Password:</label><input type='password' id='oldPass' required>"
                        "<label>New Password:</label><input type='password' id='newPass' required>"
                        "<label>Confirm New Password:</label><input type='password' id='confirmPass' required>"
                        "<button type='submit' class='danger'>Change Password</button></form></div>"
                        "</div></div>";
                    send(sock, pass_card, strlen(pass_card), 0);

                    // JavaScript part 1
                    const char *script1 =
                        "<script>"
                        "document.getElementById('useStatic').addEventListener('change',function(){"
                        "document.getElementById('staticIpFields').style.display=this.checked?'block':'none'});"
                        "function logout(){fetch('/admin/logout',{method:'POST'}).then(()=>window.location.reload())}"
                        "function regenKey(){if(confirm('Regenerate API key? Old key will stop working.')){"
                        "fetch('/admin/regenerate_key',{method:'POST'}).then(r=>r.json()).then(d=>{"
                        "if(d.success){document.getElementById('apiKey').textContent=d.api_key;alert('API key regenerated!')}})}}"
                        "function generateToken(){var dur=document.getElementById('duration').value;"
                        "fetch('/admin/generate_token',{method:'POST',body:'duration='+dur}).then(r=>r.json()).then(d=>{"
                        "if(d.success){document.getElementById('newToken').textContent=d.token;"
                        "document.getElementById('tokenDisplay').style.display='block';setTimeout(()=>document.getElementById('tokenDisplay').style.display='none',10000)}"
                        "else{alert('Error: '+d.error)}})}"
                        "document.getElementById('wifiForm').addEventListener('submit',function(e){"
                        "e.preventDefault();if(!confirm('Update WiFi configuration?'))return;"
                        "var data='admin_password='+encodeURIComponent(document.getElementById('adminPass').value)+"
                        "'&ssid='+encodeURIComponent(document.getElementById('ssid').value)+"
                        "'&password='+encodeURIComponent(document.getElementById('pass').value)+"
                        "'&use_static='+document.getElementById('useStatic').checked;"
                        "if(document.getElementById('useStatic').checked){"
                        "data+='&static_ip='+encodeURIComponent(document.getElementById('staticIp').value)+"
                        "'&static_gw='+encodeURIComponent(document.getElementById('staticGw').value)+"
                        "'&static_nm='+encodeURIComponent(document.getElementById('staticNm').value)+"
                        "'&static_dns='+encodeURIComponent(document.getElementById('staticDns').value)}"
                        "fetch('/admin/configure',{method:'POST',body:data}).then(r=>r.text()).then(()=>{alert('WiFi updated! Reconnecting...');setTimeout(updateStatus,5000)})});";
                    send(sock, script1, strlen(script1), 0);

                    // JavaScript part 2
                    const char *script2 =
                        "document.getElementById('passForm').addEventListener('submit',function(e){"
                        "e.preventDefault();var newP=document.getElementById('newPass').value;var confP=document.getElementById('confirmPass').value;"
                        "if(newP!==confP){alert('Passwords do not match!');return}"
                        "if(newP.length<6){alert('Password must be at least 6 characters');return}"
                        "var data='old_password='+encodeURIComponent(document.getElementById('oldPass').value)+"
                        "'&new_password='+encodeURIComponent(newP);"
                        "fetch('/admin/change_password',{method:'POST',body:data}).then(r=>r.json()).then(d=>{"
                        "if(d.success){alert('Password changed successfully!');document.getElementById('passForm').reset()}"
                        "else{alert('Error: '+d.error)}})});"
                        "function updateStatus(){fetch('/admin/status').then(r=>r.json()).then(d=>{"
                        "var status=d.sta_connected?'<span class=\"status-badge status-ok\">✓ Connected</span>':'<span class=\"status-badge status-error\">✗ Disconnected</span>';"
                        "document.getElementById('wifiStatus').innerHTML='<strong>Status:</strong> '+status+'<br><strong>SSID:</strong> '+d.ssid+'<br><strong>RSSI:</strong> '+d.rssi+' dBm';"
                        "var meshStatus=d.mesh_connected?'<span class=\"status-badge status-ok\">✓ Connected</span>':'<span class=\"status-badge status-error\">✗ Disconnected</span>';"
                        "var roleColor=d.mesh_role==='ROOT'?'#28a745':'#007bff';"
                        "document.getElementById('meshStatus').innerHTML='<strong>Status:</strong> '+meshStatus+'<br><strong>Role:</strong> <span style=\"color:'+roleColor+';font-weight:bold\">'+d.mesh_role+'</span><br><strong>Layer:</strong> '+d.mesh_layer+'<br><strong>Nodes:</strong> '+d.mesh_routing_size})};"
                        "updateStatus();setInterval(updateStatus,10000);";
                    send(sock, script2, strlen(script2), 0);

                    // Session timeout with dynamic value
                    char script3[512];
                    snprintf(script3, sizeof(script3),
                             "var lastActivity=Date.now();function resetTimer(){lastActivity=Date.now()}"
                             "document.addEventListener('click',resetTimer);document.addEventListener('keypress',resetTimer);"
                             "setInterval(function(){if(Date.now()-lastActivity>%d*1000){alert('Session expired due to inactivity');window.location.reload()}},60000);"
                             "</script></body></html>",
                             ADMIN_SESSION_TIMEOUT);
                    send(sock, script3, strlen(script3), 0);
                }
                close(sock);
                continue;
            }

            // Handle captive portal detection requests
            bool is_captive_detection =
                (strstr(rx_buffer, "connectivitycheck") != NULL) ||
                (strstr(rx_buffer, "msftconnecttest") != NULL) ||
                (strstr(rx_buffer, "captive.apple.com") != NULL) ||
                (strstr(rx_buffer, "clients3.google.com") != NULL) ||
                (strstr(rx_buffer, "generate_204") != NULL);

            if (is_captive_detection && !is_authenticated)
            {
                // Redirect unauthenticated clients to our portal
                const char *redirect =
                    "HTTP/1.1 302 Found\r\n"
                    "Location: http://192.168.4.1/\r\n"
                    "Connection: close\r\n\r\n";
                send(sock, redirect, strlen(redirect), 0);
                close(sock);
                continue;
            }

            // If authenticated and NOT accessing portal pages, close connection to let traffic through to internet
            bool is_portal_page = is_post_login || is_admin_page || is_admin_config || is_admin_status ||
                                  is_customer_status || is_api_token || is_api_token_disable ||
                                  is_api_token_info || is_api_token_extend ||
                                  (strstr(rx_buffer, "GET / HTTP") != NULL) || // Main portal page
                                  (strstr(rx_buffer, "GET /favicon.ico") != NULL);

            if (is_authenticated && !is_portal_page)
            {
                ESP_LOGI(TAG, "Authenticated client accessing internet - closing connection to allow direct access");
                close(sock);
                continue;
            }

            if (is_post_login)
            {
                // Extract token from POST data
                char *body = strstr(rx_buffer, "\r\n\r\n");
                if (body != NULL)
                {
                    body += 4; // Skip the \r\n\r\n

                    // Parse token=XXXXXXXX
                    char token[TOKEN_LENGTH + 1] = {0};
                    char *token_start = strstr(body, "token=");
                    if (token_start != NULL)
                    {
                        token_start += 6; // Skip "token="
                        int i = 0;
                        while (i < TOKEN_LENGTH && token_start[i] && token_start[i] != '&' && token_start[i] != '\r' && token_start[i] != '\n')
                        {
                            token[i] = token_start[i];
                            i++;
                        }
                        token[i] = '\0';

                        // Get client MAC (simplified - we'll use IP for now as proxy)
                        // In real implementation, you'd get this from WiFi station list
                        uint8_t client_mac[6] = {0};
                        memcpy(client_mac, &source_addr.sin_addr.s_addr, 4);

                        // Validate token
                        if (validate_token(token, client_mac))
                        {
                            // Add client to authenticated list
                            add_authenticated_client(source_addr.sin_addr.s_addr, client_mac);

                            // Get token info for display
                            token_info_t *token_info = get_token_info_by_string(token);

                            // Send stats page
                            send_stats_page(sock, token, token_info);
                        }
                        else
                        {
                            // Invalid token response
                            const char *error_response =
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: text/html; charset=UTF-8\r\n"
                                "Connection: close\r\n"
                                "\r\n"
                                "<!DOCTYPE html>"
                                "<html><head><meta charset='UTF-8'><title>Invalid Token</title>"
                                "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                                "<style>body{font-family:Arial;margin:40px;text-align:center;background:#f0f0f0}"
                                ".box{background:white;padding:30px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1);max-width:400px;margin:0 auto}"
                                "h1{color:#dc3545}.error{color:#666;margin-top:20px}button{background:#007bff;color:white;padding:12px;border:none;border-radius:5px;cursor:pointer;margin-top:15px}"
                                "</style></head><body><div class='box'>"
                                "<h1>✗ Invalid Token</h1>"
                                "<p>The token you entered is invalid or has expired.</p>"
                                "<button onclick='history.back()'>Try Again</button>"
                                "</div></body></html>";

                            send(sock, error_response, strlen(error_response), 0);
                        }
                    }
                }
            }
            else
            {
                // Check if user is already authenticated
                if (is_authenticated)
                {
                    // Find the authenticated client's MAC address
                    uint8_t client_mac[6] = {0};
                    for (int i = 0; i < MAX_AUTHENTICATED_CLIENTS; i++)
                    {
                        if (authenticated_clients[i].active &&
                            authenticated_clients[i].ip_addr == source_addr.sin_addr.s_addr)
                        {
                            memcpy(client_mac, authenticated_clients[i].mac, 6);
                            break;
                        }
                    }

                    // Find token by MAC address
                    token_info_t *token_info = get_token_info_by_mac(client_mac);

                    if (token_info != NULL)
                    {
                        // Show stats page for authenticated user
                        send_stats_page(sock, token_info->token, token_info);
                    }
                    else
                    {
                        // Token not found (shouldn't happen, but fallback to login)
                        ESP_LOGW(TAG, "Authenticated client has no valid token");
                        goto show_login;
                    }
                }
                else
                {
                show_login:
                    // Check if time is synced before showing login page
                    if (!is_time_valid())
                    {
                        // Show "waiting for time sync" page
                        const char *waiting_response =
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/html; charset=UTF-8\r\n"
                            "Connection: close\r\n"
                            "Refresh: 3\r\n" // Auto-refresh every 3 seconds
                            "\r\n"
                            "<!DOCTYPE html>"
                            "<html><head><meta charset='UTF-8'><title>ESP32 Portal - Initializing</title>"
                            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                            "<style>body{font-family:Arial;margin:40px;text-align:center;background:#f0f0f0}"
                            ".box{background:white;padding:30px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1);max-width:400px;margin:0 auto}"
                            "h1{color:#333}p{color:#666}.spinner{border:4px solid #f3f3f3;border-top:4px solid #007bff;border-radius:50%;"
                            "width:40px;height:40px;animation:spin 1s linear infinite;margin:20px auto}"
                            "@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}"
                            ".info{margin-top:20px;font-size:14px;color:#999}</style>"
                            "</head><body><div class='box'>"
                            "<h1>⏳ Initializing Portal</h1>"
                            "<div class='spinner'></div>"
                            "<p>Synchronizing time with network...</p>"
                            "<p class='info'>This usually takes 5-10 seconds.<br>The page will refresh automatically.</p>"
                            "</div></body></html>";
                        send(sock, waiting_response, strlen(waiting_response), 0);
                        close(sock);
                        continue;
                    }

                    // Show login page for unauthenticated users
                    const char *response =
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/html; charset=UTF-8\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                        "<!DOCTYPE html>"
                        "<html><head><meta charset='UTF-8'><title>ESP32 Portal</title>"
                        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                        "<style>body{font-family:Arial;margin:40px;text-align:center;background:#f0f0f0}"
                        ".box{background:white;padding:30px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1);max-width:400px;margin:0 auto}"
                        "h1{color:#333}p{color:#666}input{width:100%;padding:10px;margin:10px 0;border:1px solid #ddd;border-radius:5px;box-sizing:border-box}"
                        "button{background:#007bff;color:white;padding:12px;border:none;border-radius:5px;width:100%;cursor:pointer}"
                        "button:hover{background:#0056b3}.info{margin-top:20px;font-size:12px;color:#999}"
                        ".admin-link{margin-top:20px;font-size:12px;color:#007bff;text-decoration:none;display:inline-block}"
                        "</style>"
                        "</head><body><div class='box'>"
                        "<h1>🌐 ESP32 Mesh Portal</h1>"
                        "<p>Enter your access token to connect</p>"
                        "<form method='POST' action='/login'>"
                        "<input type='text' name='token' placeholder='Enter 8-character token' maxlength='8' pattern='[A-Z0-9]{8}' required>"
                        "<button type='submit'>Connect</button>"
                        "</form>"
                        "<p class='info'>Token expire count down starts after first use<br>Phase 2: Token validation active</p>"
                        "<a href='/admin' class='admin-link'>🔧 Admin Panel</a>"
                        "</div></body></html>";

                    send(sock, response, strlen(response), 0);
                }
            }

            close(sock);
        }
    }

    close(listen_sock);
    vTaskDelete(NULL);
}

// Old connect_to_router function - no longer used since we configure WiFi directly in app_main
// Kept for reference
/*
esp_err_t connect_to_router(const char *ssid, const char *password)
{
    // Function body removed - not used
}
*/

void app_main(void)
{
    ESP_LOGI(TAG, "ESP32 Mesh Portal Starting...");

    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Initialize heartbeat LED (fast blink mode)
    heartbeat_init(HEARTBEAT_LED_GPIO);
    ESP_LOGI(TAG, "✓ Heartbeat LED initialized (fast blink - waiting for WiFi)");

    // Time will be synced via SNTP after WiFi connection
    ESP_LOGI(TAG, "Time sync will occur after WiFi connection");

    // Load admin password and API key
    load_admin_password();
    load_or_generate_api_key();

    // Load existing tokens from NVS
    load_tokens_from_nvs();

    // Load WiFi credentials from NVS (or use defaults)
    load_wifi_credentials();

    // Tokens will be created via admin panel after time sync
    ESP_LOGI(TAG, "Loaded %d tokens from storage", token_count);

    // Initialize TCP/IP and WiFi
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

#if MESH_ENABLED
    // MESH MODE: Create network interfaces for mesh
    ESP_LOGI(TAG, "Starting in MESH MODE");
    ESP_ERROR_CHECK(esp_netif_create_default_wifi_mesh_netifs(&sta_netif, &ap_netif));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // Register WiFi and Mesh event handlers
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(MESH_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &mesh_event_handler,
                                                        NULL,
                                                        NULL));

    // Initialize ESP-MESH
    ESP_ERROR_CHECK(esp_mesh_init());
    ESP_LOGI(TAG, "✓ ESP-MESH initialized");

    // Configure mesh network
    mesh_cfg_t mesh_config = MESH_INIT_CONFIG_DEFAULT();

    // Set mesh ID
    memcpy((uint8_t *)&mesh_config.mesh_id, MESH_ID, 6);

    // Set mesh type to MESH_ROOT (allow this node to become root)
    mesh_config.mesh_ap.max_connection = 6;
    mesh_config.mesh_ap.nonmesh_max_connection = 0; // No non-mesh connections on mesh interface

    // Configure router connection for root node
    strncpy((char *)mesh_config.router.ssid, current_wifi_ssid, sizeof(mesh_config.router.ssid));
    strncpy((char *)mesh_config.router.password, current_wifi_pass, sizeof(mesh_config.router.password));

    ESP_ERROR_CHECK(esp_mesh_set_config(&mesh_config));

    // Set mesh topology
    ESP_ERROR_CHECK(esp_mesh_set_max_layer(MESH_MAX_LAYER));
    ESP_ERROR_CHECK(esp_mesh_set_vote_percentage(1));
    ESP_ERROR_CHECK(esp_mesh_set_xon_qsize(128));

    // Allow root node switching
    ESP_ERROR_CHECK(esp_mesh_set_ap_authmode(WIFI_AUTH_WPA2_PSK));
    ESP_ERROR_CHECK(esp_mesh_set_ap_password((uint8_t *)MESH_PASSWORD, strlen(MESH_PASSWORD)));

    // Enable self-organized networking
    ESP_ERROR_CHECK(esp_mesh_set_self_organized(true, false));

    // Enable mesh root healing
    ESP_ERROR_CHECK(esp_mesh_fix_root(false));

    // Set WiFi mode to APSTA for mesh operation
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    // Configure the guest AP (separate from mesh)
    wifi_config_t wifi_config_ap = {
        .ap = {
            .ssid = "ESP32-Guest-Portal",
            .ssid_len = strlen("ESP32-Guest-Portal"),
            .channel = MESH_CHANNEL,
            .password = "",
            .max_connection = 4,
            .authmode = WIFI_AUTH_OPEN,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config_ap));

    // Start WiFi and Mesh
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "✓ WiFi started for mesh operation");

    ESP_ERROR_CHECK(esp_mesh_start());
    ESP_LOGI(TAG, "✓ ESP-MESH started - Network: %s", MESH_ID);
    ESP_LOGI(TAG, "  → Connecting to router: %s", current_wifi_ssid);
    ESP_LOGI(TAG, "  → Guest AP: ESP32-Guest-Portal");
    ESP_LOGI(TAG, "  → Mesh Channel: %d, Max Layer: %d", MESH_CHANNEL, MESH_MAX_LAYER);

    // Wait for mesh connection
    ESP_LOGI(TAG, "Waiting for mesh network to stabilize...");
    vTaskDelay(pdMS_TO_TICKS(8000));
#else
    // STANDALONE AP MODE: Simple captive portal without mesh
    ESP_LOGI(TAG, "Starting in STANDALONE AP MODE");

    // Create AP and STA interfaces
    ap_netif = esp_netif_create_default_wifi_ap();
    sta_netif = esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // Register WiFi event handlers
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));

    // Configure WiFi for APSTA mode
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    // Configure the AP
    wifi_config_t ap_config = {
        .ap = {
            .ssid = "ESP32-Guest-Portal",
            .ssid_len = strlen("ESP32-Guest-Portal"),
            .channel = MESH_CHANNEL,
            .password = "",
            .max_connection = 4,
            .authmode = WIFI_AUTH_OPEN,
            .pmf_cfg = {
                .required = false,
            },
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));

    // Configure the STA (for router connection)
    wifi_config_t sta_config = {
        .sta = {
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {
                .capable = true,
                .required = false},
        },
    };
    strncpy((char *)sta_config.sta.ssid, current_wifi_ssid, sizeof(sta_config.sta.ssid));
    strncpy((char *)sta_config.sta.password, current_wifi_pass, sizeof(sta_config.sta.password));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));

    // Configure static IP if enabled (BEFORE starting WiFi)
    if (use_static_ip && sta_netif != NULL)
    {
        ESP_LOGI(TAG, "Configuring static IP: %s", static_ip);

        // Stop DHCP client
        esp_netif_dhcpc_stop(sta_netif);

        // Configure static IP
        esp_netif_ip_info_t ip_info;
        memset(&ip_info, 0, sizeof(esp_netif_ip_info_t));

        ip_info.ip.addr = esp_ip4addr_aton(static_ip);
        ip_info.gw.addr = esp_ip4addr_aton(static_gateway);
        ip_info.netmask.addr = esp_ip4addr_aton(static_netmask);

        esp_netif_set_ip_info(sta_netif, &ip_info);

        // Set DNS
        esp_netif_dns_info_t dns_info;
        dns_info.ip.u_addr.ip4.addr = esp_ip4addr_aton(static_dns);
        dns_info.ip.type = ESP_IPADDR_TYPE_V4;
        esp_netif_set_dns_info(sta_netif, ESP_NETIF_DNS_MAIN, &dns_info);

        ESP_LOGI(TAG, "✓ Static IP configured at startup: IP=%s, GW=%s, NM=%s, DNS=%s",
                 static_ip, static_gateway, static_netmask, static_dns);
    }

    // Start WiFi
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "✓ WiFi started - AP: ESP32-Guest-Portal");

    // Connect to router (non-blocking, will retry via event handler)
    ESP_LOGI(TAG, "WiFi STA starting, attempting connection to: %s", current_wifi_ssid);
    esp_err_t err = esp_wifi_connect();
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "Initial WiFi connect returned error (will retry): %s", esp_err_to_name(err));
    }
    ESP_LOGI(TAG, "  → Connecting to router: %s", current_wifi_ssid);

    // Wait for connection
    vTaskDelay(pdMS_TO_TICKS(3000));
#endif // MESH_ENABLED

    // Start captive portal services
    ESP_LOGI(TAG, "✓ Starting captive portal services");

#if MESH_ENABLED
    // Enable NAT for internet routing - only if we're root node
    if (esp_mesh_is_root())
    {
        esp_netif_ip_info_t ap_ip_info;
        esp_netif_get_ip_info(ap_netif, &ap_ip_info);

        esp_netif_ip_info_t sta_ip_info;
        esp_netif_get_ip_info(sta_netif, &sta_ip_info);

        // Enable NAPT on the AP interface for mesh and guest clients
        ip_napt_enable(ap_ip_info.ip.addr, 1);
        ESP_LOGI(TAG, "✓ NAT ENABLED on AP: " IPSTR " forwarding through STA: " IPSTR,
                 IP2STR(&ap_ip_info.ip), IP2STR(&sta_ip_info.ip));
        ESP_LOGI(TAG, "✓ MESH ROOT NODE: Acting as internet gateway");
    }
    else
    {
        ESP_LOGI(TAG, "✓ MESH CHILD NODE: Layer %d, relaying through parent", mesh_layer);
    }

    ESP_LOGI(TAG, "✓ MESH NETWORK ACTIVE: %s (Connected: %s)",
             MESH_ID, mesh_connected ? "YES" : "NO");
#else
    // In standalone mode, NAT is enabled automatically via enable_nat_routing() on IP_EVENT_STA_GOT_IP
    enable_nat_routing();
#endif

    ESP_LOGI(TAG, "✓ TOKEN SYSTEM ACTIVE: %d tokens loaded", token_count);
    ESP_LOGI(TAG, "Starting DNS and HTTP servers...");

    // Start DNS server for captive portal redirect
    xTaskCreate(dns_server_task, "dns_server", 4096, NULL, 5, NULL);

    // Start HTTP server for captive portal with token validation (32KB stack for large HTML pages & admin panel)
    xTaskCreate(http_server_task, "http_server", 32768, NULL, 5, NULL);

    ESP_LOGI(TAG, "✓ CAPTIVE PORTAL ACTIVE (with token validation)");

    // Keep running and monitor status
    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(10000));

#if MESH_ENABLED
        const char *role = esp_mesh_is_root() ? "ROOT" : "CHILD";
        int routing_table_size = esp_mesh_get_routing_table_size();

        ESP_LOGI(TAG, "Status: Role=%s, Layer=%d, Connected=%d, Tokens=%d, Auth=%d, Routing=%d",
                 role,
                 mesh_layer,
                 mesh_connected ? 1 : 0,
                 token_count,
                 authenticated_count,
                 routing_table_size);
#else
        ESP_LOGI(TAG, "Status: Role=CHILD, Layer=-1, Connected=0, Tokens=%d, Auth=%d, Routing=0",
                 token_count,
                 authenticated_count);
#endif
    }
}
