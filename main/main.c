#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <inttypes.h>
#include <ctype.h>
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
#include "esp_https_ota.h"
#include "esp_ota_ops.h"
#include "esp_http_client.h"
#include "esp_timer.h"
#include "driver/gpio.h"
#include "heartbeat.h"

static const char *TAG = "esp32-mesh-portal";

// Time sync state
static bool time_synced = false;
static time_t time_sync_timestamp = 0;

// OTA update state
static bool ota_in_progress = false;
static esp_ota_handle_t ota_handle = 0;
static const esp_partition_t *ota_partition = NULL;

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
#define AP_SSID_KEY "ap_ssid"
#define ADMIN_SESSION_TIMEOUT 300 // 5 minutes in seconds
#define API_KEY_LENGTH 32

// Heartbeat LED configuration
#define HEARTBEAT_LED_GPIO GPIO_NUM_2 // Built-in LED on most ESP32 boards

// Current credentials (loaded from NVS or defaults)
static char admin_password[64] = "admin123";
static char api_key[API_KEY_LENGTH + 1] = {0};
static char current_wifi_ssid[32] = MESH_ROUTER_SSID;
static char current_wifi_pass[64] = MESH_ROUTER_PASS;
static char ap_ssid[33] = MESH_ID; // Default AP SSID (1-32 chars + null terminator)

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
#define MAX_TOKENS 500 // Increased from 230 to 500 for expanded capacity
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

    // Device information (hybrid approach - stored on authentication, enhanced on-demand)
    char hostname[64];    // Device hostname from DHCP
    char device_type[32]; // Device type (iPhone, Windows PC, etc.)
    time_t first_seen;    // When device was first seen
    time_t last_seen;     // When device was last seen online
} token_info_t;

// Blob structure for storing all tokens in a single NVS entry
typedef struct
{
    token_info_t tokens[MAX_TOKENS];
    int token_count;
} token_blob_t;

static token_blob_t token_blob;

// Remove redundant active_tokens array - work directly with token_blob.tokens
// static token_info_t active_tokens[MAX_TOKENS]; // REMOVED - saves 36KB RAM
// static int token_count = 0; // REMOVED - use token_blob.token_count instead

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

// ==================== MAC Filtering (Blacklist/Whitelist) ====================
#define MAX_BLACKLIST_ENTRIES 200
#define MAX_WHITELIST_ENTRIES 200
#define MAC_FILTER_REASON_LENGTH 32
#define MAC_FILTER_NOTE_LENGTH 32

// Blacklist entry - Devices blocked from network access
typedef struct
{
    uint8_t mac[6];                        // MAC address
    char token[TOKEN_LENGTH + 1];          // Token that was used to identify device
    time_t added;                          // When added to blacklist
    char reason[MAC_FILTER_REASON_LENGTH]; // Reason for blocking
    bool active;                           // Entry is in use
} blacklist_entry_t;

// Whitelist entry - VIP devices with permanent bypass (no token needed)
typedef struct
{
    uint8_t mac[6];                    // MAC address
    char token[TOKEN_LENGTH + 1];      // Token that granted whitelist status
    time_t added;                      // When added to whitelist
    char note[MAC_FILTER_NOTE_LENGTH]; // Optional note
    bool active;                       // Entry is in use
} whitelist_entry_t;

// Blob structure for storing all blacklist entries in a single NVS entry
typedef struct
{
    blacklist_entry_t entries[MAX_BLACKLIST_ENTRIES];
    int entry_count;
} blacklist_blob_t;

static blacklist_blob_t blacklist_blob;

// Blob structure for storing all whitelist entries in a single NVS entry
typedef struct
{
    whitelist_entry_t entries[MAX_WHITELIST_ENTRIES];
    int entry_count;
} whitelist_blob_t;

static whitelist_blob_t whitelist_blob;

// Remove redundant arrays - work directly with blob structures
// static blacklist_entry_t blacklist[MAX_BLACKLIST_ENTRIES]; // REMOVED - use blacklist_blob.entries
// static int blacklist_count = 0; // REMOVED - use blacklist_blob.entry_count
// static whitelist_entry_t whitelist[MAX_WHITELIST_ENTRIES]; // REMOVED - use whitelist_blob.entries
// static int whitelist_count = 0; // REMOVED - use whitelist_blob.entry_count

// NVS keys for MAC filtering
#define NVS_BLACKLIST_COUNT "bl_count"
#define NVS_BLACKLIST_PREFIX "bl_"
#define NVS_WHITELIST_COUNT "wl_count"
#define NVS_WHITELIST_PREFIX "wl_"

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
    return token_blob.token_count;
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

// Sanitize string for JSON output by replacing non-printable characters
static void sanitize_string(const char *input, char *output, size_t max_len)
{
    if (!input || !output || max_len == 0)
        return;

    size_t i = 0;
    for (; i < max_len - 1 && input[i] != '\0'; i++)
    {
        output[i] = isprint((unsigned char)input[i]) ? input[i] : '?';
    }
    output[i] = '\0';
}

// Save all tokens as a single blob to NVS
static esp_err_t save_tokens_blob_to_nvs(void)
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open_from_partition("nvs_tokens", "tokens", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Error opening NVS tokens partition: %s", esp_err_to_name(err));
        return err;
    }

    // Copy current token_blob.tokens to token_blob (already in sync)
    // memcpy(token_blob.tokens, active_tokens, sizeof(active_tokens)); // REMOVED

    // Save entire token blob
    err = nvs_set_blob(nvs_handle, "token_blob", &token_blob, sizeof(token_blob_t));
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Error saving token blob to NVS: %s", esp_err_to_name(err));
        // Short-term mitigation: erase only the tokens namespace if space error
        if (err == ESP_ERR_NVS_NOT_ENOUGH_SPACE)
        {
            ESP_LOGW(TAG, "NVS space exhausted in tokens namespace, attempting namespace recovery...");

            // Get stats before erase
            nvs_stats_t nvs_stats;
            err = nvs_get_stats("nvs_tokens", &nvs_stats);
            if (err == ESP_OK)
            {
                ESP_LOGI(TAG, "DEBUG: NVS stats before erase - used: %d, free: %d, total: %d",
                         nvs_stats.used_entries, nvs_stats.free_entries, nvs_stats.total_entries);
            }

            // Try to erase all keys in the tokens namespace to free space
            ESP_LOGI(TAG, "DEBUG: Calling nvs_erase_all on tokens namespace...");
            err = nvs_erase_all(nvs_handle);
            ESP_LOGI(TAG, "DEBUG: nvs_erase_all returned: %s", esp_err_to_name(err));

            err = nvs_commit(nvs_handle);
            ESP_LOGI(TAG, "DEBUG: nvs_commit after erase returned: %s", esp_err_to_name(err));

            // Get stats after erase
            err = nvs_get_stats("nvs_tokens", &nvs_stats);
            if (err == ESP_OK)
            {
                ESP_LOGI(TAG, "DEBUG: NVS stats after erase - used: %d, free: %d, total: %d",
                         nvs_stats.used_entries, nvs_stats.free_entries, nvs_stats.total_entries);
            }

            nvs_close(nvs_handle);

            ESP_LOGI(TAG, "Erased tokens namespace, retrying save...");
            err = nvs_open_from_partition("nvs_tokens", "tokens", NVS_READWRITE, &nvs_handle);
            if (err != ESP_OK)
            {
                ESP_LOGE(TAG, "DEBUG: Failed to reopen tokens partition after erase: %s", esp_err_to_name(err));
                return err;
            }

            // Get stats after reopen
            err = nvs_get_stats("nvs_tokens", &nvs_stats);
            if (err == ESP_OK)
            {
                ESP_LOGI(TAG, "DEBUG: NVS stats after reopen - used: %d, free: %d, total: %d",
                         nvs_stats.used_entries, nvs_stats.free_entries, nvs_stats.total_entries);
            }

            err = nvs_set_blob(nvs_handle, "token_blob", &token_blob, sizeof(token_blob_t));
            if (err == ESP_OK)
            {
                err = nvs_commit(nvs_handle);
                ESP_LOGI(TAG, "Token blob saved to NVS after namespace recovery");
            }
            else
            {
                ESP_LOGE(TAG, "Failed to save token blob even after namespace erase: %s", esp_err_to_name(err));

                // Additional debugging: try to save a smaller test blob
                char test_data[10] = "test";
                esp_err_t test_err = nvs_set_str(nvs_handle, "test_key", test_data);
                ESP_LOGI(TAG, "DEBUG: Test save result: %s", esp_err_to_name(test_err));

                if (test_err == ESP_OK)
                {
                    test_err = nvs_commit(nvs_handle);
                    ESP_LOGI(TAG, "DEBUG: Test commit result: %s", esp_err_to_name(test_err));
                }

                // Check global NVS stats
                nvs_stats_t global_stats;
                esp_err_t global_err = nvs_get_stats(NULL, &global_stats);
                if (global_err == ESP_OK)
                {
                    ESP_LOGI(TAG, "DEBUG: Global NVS stats - used: %d, free: %d, total: %d",
                             global_stats.used_entries, global_stats.free_entries, global_stats.total_entries);
                }
                else
                {
                    ESP_LOGI(TAG, "DEBUG: Failed to get global NVS stats: %s", esp_err_to_name(global_err));
                }
            }
        }
    }
    else
    {
        err = nvs_commit(nvs_handle);
        ESP_LOGI(TAG, "Token blob saved to NVS (%d tokens)", token_blob.token_count);
    }

    nvs_close(nvs_handle);
    return err;
}

// Load all tokens from NVS blob
static void load_tokens_blob_from_nvs(void)
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open_from_partition("nvs_tokens", "tokens", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGI(TAG, "No existing token blob found in NVS tokens partition");
        return;
    }

    size_t required_size = sizeof(token_blob_t);
    err = nvs_get_blob(nvs_handle, "token_blob", &token_blob, &required_size);

    if (err != ESP_OK)
    {
        ESP_LOGI(TAG, "No token blob found in NVS (%s)", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return;
    }

    // Validate tokens directly in token_blob and update count
    // memcpy(active_tokens, token_blob.tokens, sizeof(active_tokens)); // REMOVED
    int valid_count = 0; // Will replace token_count

    time_t now = time(NULL);
    for (int i = 0; i < token_blob.token_count && valid_count < MAX_TOKENS; i++)
    {
        if (token_blob.tokens[i].active)
        {
            bool expired = false;

            // Check time expiration
            if (token_blob.tokens[i].first_use > 0)
            {
                time_t token_expires = token_blob.tokens[i].first_use +
                                       (token_blob.tokens[i].duration_minutes * 60);
                if (now > token_expires)
                {
                    ESP_LOGI(TAG, "Token %s expired (time), removing", token_blob.tokens[i].token);
                    expired = true;
                }
            }

            // Check bandwidth limits
            if (token_blob.tokens[i].bandwidth_down_mb > 0 &&
                token_blob.tokens[i].bandwidth_used_down >= token_blob.tokens[i].bandwidth_down_mb)
            {
                ESP_LOGI(TAG, "Token %s expired (bandwidth down), removing", token_blob.tokens[i].token);
                expired = true;
            }
            if (token_blob.tokens[i].bandwidth_up_mb > 0 &&
                token_blob.tokens[i].bandwidth_used_up >= token_blob.tokens[i].bandwidth_up_mb)
            {
                ESP_LOGI(TAG, "Token %s expired (bandwidth up), removing", token_blob.tokens[i].token);
                expired = true;
            }

            if (expired)
            {
                token_blob.tokens[i].active = false;
            }
            else
            {
                ESP_LOGI(TAG, "Loaded token %s (used %lu times, %d devices)",
                         token_blob.tokens[i].token,
                         token_blob.tokens[i].usage_count,
                         token_blob.tokens[i].device_count);
                valid_count++;
            }
        }
    }

    // Update token count after validation
    token_blob.token_count = valid_count;

    nvs_close(nvs_handle);
    ESP_LOGI(TAG, "Loaded %d active tokens from NVS blob", token_blob.token_count);
}

// ==================== MAC Filtering NVS Functions ====================

// Save blacklist to NVS
static esp_err_t save_blacklist_to_nvs(void)
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open_from_partition("nvs_blacklist", "mac_filter", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Error opening NVS blacklist partition: %s", esp_err_to_name(err));
        return err;
    }

    // Save entire blacklist blob
    err = nvs_set_blob(nvs_handle, "blacklist_blob", &blacklist_blob, sizeof(blacklist_blob_t));
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Error saving blacklist blob: %s", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return err;
    }

    err = nvs_commit(nvs_handle);
    nvs_close(nvs_handle);

    ESP_LOGI(TAG, "✓ Saved %d blacklist entries to NVS blob", blacklist_blob.entry_count);
    return err;
}

// Load blacklist from NVS
static void load_blacklist_from_nvs(void)
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open_from_partition("nvs_blacklist", "mac_filter", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGI(TAG, "No existing blacklist found in NVS");
        return;
    }

    // Load entire blacklist blob
    size_t required_size = sizeof(blacklist_blob_t);
    err = nvs_get_blob(nvs_handle, "blacklist_blob", &blacklist_blob, &required_size);

    if (err == ESP_OK)
    {
        ESP_LOGI(TAG, "✓ Loaded %d blacklist entries from NVS blob", blacklist_blob.entry_count);
    }
    else
    {
        ESP_LOGI(TAG, "No blacklist blob found, starting with empty blacklist");
        memset(&blacklist_blob, 0, sizeof(blacklist_blob_t));
    }

    nvs_close(nvs_handle);
}

// Save whitelist to NVS
static esp_err_t save_whitelist_to_nvs(void)
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open_from_partition("nvs_whitelist", "mac_filter", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Error opening NVS whitelist partition: %s", esp_err_to_name(err));
        return err;
    }

    // Save entire whitelist blob
    err = nvs_set_blob(nvs_handle, "whitelist_blob", &whitelist_blob, sizeof(whitelist_blob_t));
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Error saving whitelist blob: %s", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return err;
    }

    err = nvs_commit(nvs_handle);
    nvs_close(nvs_handle);

    ESP_LOGI(TAG, "✓ Saved %d whitelist entries to NVS blob", whitelist_blob.entry_count);
    return err;
}

// Load whitelist from NVS
static void load_whitelist_from_nvs(void)
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open_from_partition("nvs_whitelist", "mac_filter", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGI(TAG, "No existing whitelist found in NVS");
        return;
    }

    // Load entire whitelist blob
    size_t required_size = sizeof(whitelist_blob_t);
    err = nvs_get_blob(nvs_handle, "whitelist_blob", &whitelist_blob, &required_size);

    if (err == ESP_OK)
    {
        ESP_LOGI(TAG, "✓ Loaded %d whitelist entries from NVS blob", whitelist_blob.entry_count);
    }
    else
    {
        ESP_LOGI(TAG, "No whitelist blob found, starting with empty whitelist");
        memset(&whitelist_blob, 0, sizeof(whitelist_blob_t));
    }

    nvs_close(nvs_handle);
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

// Validate AP SSID format
static bool is_valid_ssid(const char *ssid)
{
    if (ssid == NULL)
    {
        return false;
    }

    size_t len = strlen(ssid);

    // Length check (WiFi standard: 1-32 bytes)
    if (len < 1 || len > 32)
    {
        ESP_LOGW(TAG, "Invalid SSID length: %zu (must be 1-32)", len);
        return false;
    }

    // Character validation (printable ASCII: 32-126)
    for (size_t i = 0; i < len; i++)
    {
        if (ssid[i] < 32 || ssid[i] > 126)
        {
            ESP_LOGW(TAG, "Invalid SSID character at position %zu: 0x%02X", i, (uint8_t)ssid[i]);
            return false;
        }
    }

    ESP_LOGI(TAG, "✓ SSID validation passed: \"%s\" (%zu chars)", ssid, len);
    return true;
}

// Forward declaration for cleanup function (needed by create_new_token_with_params)
static void cleanup_expired_tokens(void);

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

    // Validate duration first (before checking token count)
    if (duration_minutes < TOKEN_MIN_DURATION_MINUTES || duration_minutes > TOKEN_MAX_DURATION_MINUTES)
    {
        ESP_LOGE(TAG, "Invalid duration: %lu minutes (must be %d-%d)",
                 duration_minutes, TOKEN_MIN_DURATION_MINUTES, TOKEN_MAX_DURATION_MINUTES);
        return ESP_ERR_INVALID_ARG;
    }

    // If at or near token limit, run cleanup first to free expired slots
    if (token_blob.token_count >= MAX_TOKENS - 5)
    {
        ESP_LOGI(TAG, "Token count (%d) near limit (%d), running cleanup first...",
                 token_blob.token_count, MAX_TOKENS);
        cleanup_expired_tokens();
    }

    // Check token limit after cleanup
    if (token_blob.token_count >= MAX_TOKENS)
    {
        ESP_LOGE(TAG, "Maximum token limit reached: token_count=%d, MAX_TOKENS=%d",
                 token_blob.token_count, MAX_TOKENS);
        return ESP_ERR_NO_MEM;
    }

    token_info_t new_token;
    memset(&new_token, 0, sizeof(token_info_t)); // Initialize all fields to 0
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

    // Add to token blob
    memcpy(&token_blob.tokens[token_blob.token_count], &new_token, sizeof(token_info_t));
    token_blob.token_count++;

    // Save all tokens to NVS blob
    esp_err_t err = save_tokens_blob_to_nvs();
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to create token - NVS save error: %s (0x%x)",
                 esp_err_to_name(err), err);
        // Rollback the addition
        token_blob.token_count--;
        return err;
    }

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

// Forward declarations for MAC filtering functions
static bool is_mac_blacklisted(const uint8_t *mac);
static bool is_mac_whitelisted(const uint8_t *mac);

// Validate token and bind to client MAC
// Device information capture functions
static void detect_device_type(const char *hostname, char *device_type, size_t max_len)
{
    if (!hostname || strlen(hostname) == 0)
    {
        strncpy(device_type, "Unknown", max_len);
        return;
    }

    // iOS devices
    if (strstr(hostname, "iPhone") || strstr(hostname, "iPad") || strstr(hostname, "iPod"))
    {
        strncpy(device_type, "Apple iOS", max_len);
    }
    // macOS devices
    else if (strstr(hostname, "MacBook") || strstr(hostname, "iMac") || strstr(hostname, "Mac-mini"))
    {
        strncpy(device_type, "Apple macOS", max_len);
    }
    // Android devices
    else if (strstr(hostname, "android-") || strstr(hostname, "Android") || strstr(hostname, "SM-") || strstr(hostname, "Pixel"))
    {
        strncpy(device_type, "Android", max_len);
    }
    // Windows devices
    else if (strstr(hostname, "DESKTOP-") || strstr(hostname, "LAPTOP-") || strstr(hostname, "WIN-"))
    {
        strncpy(device_type, "Windows PC", max_len);
    }
    // Linux devices
    else if (strstr(hostname, "ubuntu") || strstr(hostname, "linux") || strstr(hostname, "debian"))
    {
        strncpy(device_type, "Linux", max_len);
    }
    // Generic patterns
    else if (strstr(hostname, "phone") || strstr(hostname, "mobile"))
    {
        strncpy(device_type, "Mobile Device", max_len);
    }
    else if (strstr(hostname, "laptop") || strstr(hostname, "notebook"))
    {
        strncpy(device_type, "Laptop", max_len);
    }
    else if (strstr(hostname, "desktop") || strstr(hostname, "pc"))
    {
        strncpy(device_type, "Desktop PC", max_len);
    }
    // Default to generic device
    else
    {
        strncpy(device_type, "Network Device", max_len);
    }
}

static void capture_device_info(token_info_t *token, const uint8_t *client_mac)
{
    time_t now = time(NULL);

    // Try to get DHCP client info for hostname
    esp_netif_pair_mac_ip_t pair;

    if (ap_netif && esp_netif_dhcps_get_clients_by_mac(ap_netif, 1, &pair) == ESP_OK)
    {
        // Check if this MAC matches our client
        if (memcmp(pair.mac, client_mac, 6) == 0)
        {
            // Get hostname from DHCP lease (if available)
            // Note: ESP-IDF DHCP server doesn't directly expose hostname,
            // but we can infer from common patterns or store when available

            // For now, use a placeholder hostname based on MAC
            char default_hostname[64];
            snprintf(default_hostname, sizeof(default_hostname),
                     "device-%02x%02x%02x",
                     client_mac[3], client_mac[4], client_mac[5]);

            // Only set hostname if not already set
            if (strlen(token->hostname) == 0)
            {
                strncpy(token->hostname, default_hostname, sizeof(token->hostname) - 1);
                detect_device_type(token->hostname, token->device_type, sizeof(token->device_type));
            }

            // Update last seen time
            token->last_seen = now;

            // Set first seen time if not set
            if (token->first_seen == 0)
            {
                token->first_seen = now;
            }

            ESP_LOGI(TAG, "Device info captured: MAC=%02X:%02X:%02X:%02X:%02X:%02X, Hostname=%s, Type=%s",
                     client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
                     token->hostname, token->device_type);
        }
    }
    else
    {
        // Fallback: set basic device info without DHCP data
        if (strlen(token->hostname) == 0)
        {
            char fallback_hostname[64];
            snprintf(fallback_hostname, sizeof(fallback_hostname),
                     "device-%02x%02x%02x",
                     client_mac[3], client_mac[4], client_mac[5]);
            strncpy(token->hostname, fallback_hostname, sizeof(token->hostname) - 1);
            detect_device_type(token->hostname, token->device_type, sizeof(token->device_type));
        }

        token->last_seen = now;
        if (token->first_seen == 0)
        {
            token->first_seen = now;
        }
    }
}

static bool check_device_online(const uint8_t *client_mac, uint32_t *current_ip)
{
    esp_netif_pair_mac_ip_t pair;

    if (!ap_netif)
    {
        return false;
    }

    // Get DHCP client list
    esp_netif_dhcps_get_clients_by_mac(ap_netif, 1, &pair);

    // Check if MAC is in DHCP leases (indicates device is online)
    if (memcmp(pair.mac, client_mac, 6) == 0)
    {
        if (current_ip)
        {
            *current_ip = pair.ip.addr;
        }
        return true;
    }

    return false;
}

// OTA firmware validation functions
static bool validate_esp32_binary(const uint8_t *data, size_t size)
{
    if (size < 4)
    {
        return false;
    }

    // Check ESP32 binary magic bytes (0xE9)
    if (data[0] != 0xE9)
    {
        ESP_LOGW(TAG, "Invalid ESP32 binary: wrong magic byte 0x%02X (expected 0xE9)", data[0]);
        return false;
    }

    // Basic size validation - should be reasonable for ESP32 firmware
    if (size < 1024 || size > 2 * 1024 * 1024)
    { // 1KB to 2MB
        ESP_LOGW(TAG, "Invalid ESP32 binary size: %d bytes", size);
        return false;
    }

    // Check for basic binary structure (segment count should be reasonable)
    if (size >= 8)
    {
        uint8_t segment_count = data[4];
        if (segment_count == 0 || segment_count > 16)
        {
            ESP_LOGW(TAG, "Invalid ESP32 binary: suspicious segment count %d", segment_count);
            return false;
        }
    }

    return true;
}

static bool validate_firmware_for_ota(const uint8_t *data, size_t size)
{
    // Get OTA partition info
    const esp_partition_t *ota_partition = esp_ota_get_next_update_partition(NULL);
    if (!ota_partition)
    {
        ESP_LOGE(TAG, "No OTA partition available for validation");
        return false;
    }

    // Check if firmware fits in partition
    if (size > ota_partition->size)
    {
        ESP_LOGW(TAG, "Firmware too large: %" PRIu32 " bytes > partition size %" PRIu32 " bytes", (uint32_t)size, ota_partition->size);
        return false;
    }

    // Leave some buffer space (at least 64KB free)
    size_t min_free_space = 64 * 1024;
    if (size > ota_partition->size - min_free_space)
    {
        ESP_LOGW(TAG, "Firmware leaves insufficient space: %" PRIu32 " bytes free < %" PRIu32 " bytes minimum",
                 (uint32_t)(ota_partition->size - size), (uint32_t)min_free_space);
        return false;
    }

    // Validate ESP32 binary format
    if (!validate_esp32_binary(data, size))
    {
        ESP_LOGW(TAG, "Firmware failed ESP32 binary validation");
        return false;
    }

    ESP_LOGI(TAG, "Firmware validation passed: size=%" PRIu32 " bytes, partition=%s (%" PRIu32 " bytes free)",
             (uint32_t)size, ota_partition->label, (uint32_t)(ota_partition->size - size));

    return true;
}

static bool validate_token(const char *token, const uint8_t *client_mac)
{
    // ===== MAC FILTERING CHECKS =====
    // Check blacklist FIRST - Always block blacklisted devices
    if (is_mac_blacklisted(client_mac))
    {
        ESP_LOGW(TAG, "✗ Blacklisted MAC attempt: %02X:%02X:%02X:%02X:%02X:%02X",
                 client_mac[0], client_mac[1], client_mac[2],
                 client_mac[3], client_mac[4], client_mac[5]);
        return false;
    }

    // Check whitelist SECOND - VIP bypass (no token needed)
    if (is_mac_whitelisted(client_mac))
    {
        ESP_LOGI(TAG, "✓ Whitelisted MAC (VIP bypass): %02X:%02X:%02X:%02X:%02X:%02X",
                 client_mac[0], client_mac[1], client_mac[2],
                 client_mac[3], client_mac[4], client_mac[5]);
        return true; // Grant access immediately, no token validation needed
    }

    // ===== NORMAL TOKEN VALIDATION =====
    // Cannot validate tokens without valid time
    if (!is_time_valid())
    {
        ESP_LOGW(TAG, "Cannot validate token: system time not synced");
        return false;
    }

    time_t now = time(NULL);
    ESP_LOGI(TAG, "DEBUG: validate_token - now=%lld, time_synced=%d", (long long)now, time_synced);

    for (int i = 0; i < token_blob.token_count; i++)
    {
        if (!token_blob.tokens[i].active)
            continue;

        if (strcmp(token_blob.tokens[i].token, token) == 0)
        {
            // Set first use time if not set
            if (token_blob.tokens[i].first_use == 0)
            {
                token_blob.tokens[i].first_use = now;
                ESP_LOGI(TAG, "Token %s first use at %lld (now=%lld)", token, (long long)token_blob.tokens[i].first_use, (long long)now);
            }

            // Update last use time on every validation (for multi-token handling)
            token_blob.tokens[i].last_use = now;

            // Check time-based expiration (from first use)
            time_t token_expires = token_blob.tokens[i].first_use + (token_blob.tokens[i].duration_minutes * 60);
            if (now > token_expires)
            {
                ESP_LOGW(TAG, "Token %s has expired (time limit)", token);
                token_blob.tokens[i].active = false;
                save_tokens_blob_to_nvs();
                return false;
            }

            // Check bandwidth expiration
            if (token_blob.tokens[i].bandwidth_down_mb > 0 &&
                token_blob.tokens[i].bandwidth_used_down >= token_blob.tokens[i].bandwidth_down_mb)
            {
                ESP_LOGW(TAG, "Token %s exceeded download limit", token);
                token_blob.tokens[i].active = false;
                save_tokens_blob_to_nvs();
                return false;
            }
            if (token_blob.tokens[i].bandwidth_up_mb > 0 &&
                token_blob.tokens[i].bandwidth_used_up >= token_blob.tokens[i].bandwidth_up_mb)
            {
                ESP_LOGW(TAG, "Token %s exceeded upload limit", token);
                token_blob.tokens[i].active = false;
                save_tokens_blob_to_nvs();
                return false;
            }

            // Check if this MAC is already registered
            int mac_index = -1;
            for (int j = 0; j < token_blob.tokens[i].device_count; j++)
            {
                if (memcmp(token_blob.tokens[i].client_macs[j], client_mac, 6) == 0)
                {
                    mac_index = j;
                    break;
                }
            }

            if (mac_index == -1)
            {
                // New device - check if we can add it
                if (token_blob.tokens[i].device_count >= MAX_DEVICES_PER_TOKEN)
                {
                    ESP_LOGW(TAG, "Token %s already has %d devices (max allowed)",
                             token, MAX_DEVICES_PER_TOKEN);
                    return false;
                }

                // Add this MAC
                memcpy(token_blob.tokens[i].client_macs[token_blob.tokens[i].device_count], client_mac, 6);
                token_blob.tokens[i].device_count++;

                // Capture device information for the new device
                capture_device_info(&token_blob.tokens[i], client_mac);

                ESP_LOGI(TAG, "Token %s bound to device %d: %02X:%02X:%02X:%02X:%02X:%02X (%s)",
                         token, token_blob.tokens[i].device_count,
                         client_mac[0], client_mac[1], client_mac[2],
                         client_mac[3], client_mac[4], client_mac[5],
                         token_blob.tokens[i].device_type);
            }

            // Increment usage count
            token_blob.tokens[i].usage_count++;
            save_tokens_blob_to_nvs();

            ESP_LOGI(TAG, "✓ Token %s validated (usage: %lu)", token, token_blob.tokens[i].usage_count);
            return true;
        }
    }

    ESP_LOGW(TAG, "✗ Invalid token: %s", token);
    return false;
}

// Get token info by token string (helper function)
static token_info_t *get_token_info_by_string(const char *token)
{
    for (int i = 0; i < token_blob.token_count; i++)
    {
        if (token_blob.tokens[i].active && strcmp(token_blob.tokens[i].token, token) == 0)
        {
            return &token_blob.tokens[i];
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

    for (int i = 0; i < token_blob.token_count; i++)
    {
        if (!token_blob.tokens[i].active)
        {
            continue;
        }

        bool expired = false;
        const char *reason = NULL;

        // Check time-based expiration
        if (token_blob.tokens[i].first_use > 0)
        {
            time_t token_expires = token_blob.tokens[i].first_use +
                                   (token_blob.tokens[i].duration_minutes * 60);
            if (now > token_expires)
            {
                expired = true;
                reason = "time limit";
            }
        }

        // Check bandwidth limits
        if (!expired && token_blob.tokens[i].bandwidth_down_mb > 0 &&
            token_blob.tokens[i].bandwidth_used_down >= token_blob.tokens[i].bandwidth_down_mb)
        {
            expired = true;
            reason = "bandwidth down limit";
        }

        if (!expired && token_blob.tokens[i].bandwidth_up_mb > 0 &&
            token_blob.tokens[i].bandwidth_used_up >= token_blob.tokens[i].bandwidth_up_mb)
        {
            expired = true;
            reason = "bandwidth up limit";
        }

        if (expired)
        {
            ESP_LOGI(TAG, "🧹 Cleaning up expired token %s (%s)",
                     token_blob.tokens[i].token, reason);

            // Mark as inactive in memory
            token_blob.tokens[i].active = false;

            cleaned++;
        }
    }

    // Compact the active tokens array by removing inactive entries
    if (cleaned > 0)
    {
        int write_idx = 0;
        for (int read_idx = 0; read_idx < token_blob.token_count; read_idx++)
        {
            if (token_blob.tokens[read_idx].active)
            {
                if (write_idx != read_idx)
                {
                    token_blob.tokens[write_idx] = token_blob.tokens[read_idx];
                }
                write_idx++;
            }
        }
        token_blob.token_count = write_idx;

        ESP_LOGI(TAG, "🧹 Cleanup complete: %d token(s) removed, %d active token(s) remaining",
                 cleaned, token_blob.token_count);

        // Persist the cleaned state to NVS blob
        save_tokens_blob_to_nvs();
    }
}

// ==================== MAC Filtering Functions ====================

// Check if a MAC address is blacklisted
static bool is_mac_blacklisted(const uint8_t *mac)
{
    for (int i = 0; i < blacklist_blob.entry_count && i < MAX_BLACKLIST_ENTRIES; i++)
    {
        if (blacklist_blob.entries[i].active && memcmp(blacklist_blob.entries[i].mac, mac, 6) == 0)
        {
            ESP_LOGD(TAG, "MAC %02X:%02X:%02X:%02X:%02X:%02X is blacklisted",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return true;
        }
    }
    return false;
}

// Check if a MAC address is whitelisted
static bool is_mac_whitelisted(const uint8_t *mac)
{
    for (int i = 0; i < whitelist_blob.entry_count && i < MAX_WHITELIST_ENTRIES; i++)
    {
        if (whitelist_blob.entries[i].active && memcmp(whitelist_blob.entries[i].mac, mac, 6) == 0)
        {
            ESP_LOGD(TAG, "MAC %02X:%02X:%02X:%02X:%02X:%02X is whitelisted (VIP bypass)",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return true;
        }
    }
    return false;
}

// Remove MAC from whitelist (used when adding to blacklist)
static esp_err_t remove_from_whitelist(const uint8_t *mac)
{
    for (int i = 0; i < whitelist_blob.entry_count && i < MAX_WHITELIST_ENTRIES; i++)
    {
        if (whitelist_blob.entries[i].active && memcmp(whitelist_blob.entries[i].mac, mac, 6) == 0)
        {
            whitelist_blob.entries[i].active = false;
            whitelist_blob.entry_count--;
            ESP_LOGI(TAG, "Removed MAC %02X:%02X:%02X:%02X:%02X:%02X from whitelist",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return ESP_OK;
        }
    }
    return ESP_ERR_NOT_FOUND;
}

// Remove MAC from blacklist (used when adding to whitelist)
static esp_err_t remove_from_blacklist(const uint8_t *mac)
{
    for (int i = 0; i < blacklist_blob.entry_count && i < MAX_BLACKLIST_ENTRIES; i++)
    {
        if (blacklist_blob.entries[i].active && memcmp(blacklist_blob.entries[i].mac, mac, 6) == 0)
        {
            blacklist_blob.entries[i].active = false;
            blacklist_blob.entry_count--;
            ESP_LOGI(TAG, "Removed MAC %02X:%02X:%02X:%02X:%02X:%02X from blacklist",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return ESP_OK;
        }
    }
    return ESP_ERR_NOT_FOUND;
}

// Add MAC to blacklist
static esp_err_t add_to_blacklist(const uint8_t *mac, const char *token, const char *reason)
{
    // Check if already blacklisted
    if (is_mac_blacklisted(mac))
    {
        ESP_LOGW(TAG, "MAC already blacklisted");
        return ESP_ERR_INVALID_STATE;
    }

    // Remove from whitelist if present (mutual exclusivity)
    remove_from_whitelist(mac);

    // Find empty slot
    for (int i = 0; i < MAX_BLACKLIST_ENTRIES; i++)
    {
        if (!blacklist_blob.entries[i].active)
        {
            memcpy(blacklist_blob.entries[i].mac, mac, 6);
            strncpy(blacklist_blob.entries[i].token, token, TOKEN_LENGTH);
            blacklist_blob.entries[i].token[TOKEN_LENGTH] = '\0';
            blacklist_blob.entries[i].added = time(NULL);
            if (reason)
            {
                strncpy(blacklist_blob.entries[i].reason, reason, MAC_FILTER_REASON_LENGTH - 1);
                blacklist_blob.entries[i].reason[MAC_FILTER_REASON_LENGTH - 1] = '\0';
            }
            else
            {
                blacklist_blob.entries[i].reason[0] = '\0';
            }
            blacklist_blob.entries[i].active = true;
            blacklist_blob.entry_count++;

            ESP_LOGI(TAG, "✓ Added MAC %02X:%02X:%02X:%02X:%02X:%02X to blacklist (token: %s)",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], token);
            return ESP_OK;
        }
    }

    ESP_LOGW(TAG, "Blacklist full (max %d entries)", MAX_BLACKLIST_ENTRIES);
    return ESP_ERR_NO_MEM;
}

// Add MAC to whitelist
static esp_err_t add_to_whitelist(const uint8_t *mac, const char *token, const char *note)
{
    // Check if already whitelisted
    if (is_mac_whitelisted(mac))
    {
        ESP_LOGW(TAG, "MAC already whitelisted");
        return ESP_ERR_INVALID_STATE;
    }

    // Remove from blacklist if present (mutual exclusivity)
    remove_from_blacklist(mac);

    // Find empty slot
    for (int i = 0; i < MAX_WHITELIST_ENTRIES; i++)
    {
        if (!whitelist_blob.entries[i].active)
        {
            memcpy(whitelist_blob.entries[i].mac, mac, 6);
            strncpy(whitelist_blob.entries[i].token, token, TOKEN_LENGTH);
            whitelist_blob.entries[i].token[TOKEN_LENGTH] = '\0';
            whitelist_blob.entries[i].added = time(NULL);
            if (note)
            {
                strncpy(whitelist_blob.entries[i].note, note, MAC_FILTER_NOTE_LENGTH - 1);
                whitelist_blob.entries[i].note[MAC_FILTER_NOTE_LENGTH - 1] = '\0';
            }
            else
            {
                whitelist_blob.entries[i].note[0] = '\0';
            }
            whitelist_blob.entries[i].active = true;
            whitelist_blob.entry_count++;

            ESP_LOGI(TAG, "✓ Added MAC %02X:%02X:%02X:%02X:%02X:%02X to whitelist (VIP bypass, token: %s)",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], token);
            return ESP_OK;
        }
    }

    ESP_LOGW(TAG, "Whitelist full (max %d entries)", MAX_WHITELIST_ENTRIES);
    return ESP_ERR_NO_MEM;
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
    for (int i = 0; i < token_blob.token_count; i++)
    {
        if (!token_blob.tokens[i].active)
            continue;

        // Check if this MAC is registered with the token
        for (int j = 0; j < token_blob.tokens[i].device_count; j++)
        {
            if (memcmp(token_blob.tokens[i].client_macs[j], mac, 6) == 0)
            {
                // Found a token with this MAC - check if it's the most recent
                if (token_blob.tokens[i].last_use > most_recent_use)
                {
                    most_recent_use = token_blob.tokens[i].last_use;
                    most_recent_token = &token_blob.tokens[i];
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

// Save AP SSID to NVS
static esp_err_t save_ap_ssid(const char *ssid)
{
    if (!is_valid_ssid(ssid))
    {
        ESP_LOGE(TAG, "Cannot save invalid SSID");
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("storage", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Error opening NVS for AP SSID: %s", esp_err_to_name(err));
        return err;
    }

    err = nvs_set_str(nvs_handle, AP_SSID_KEY, ssid);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Error saving AP SSID: %s", esp_err_to_name(err));
        nvs_close(nvs_handle);
        return err;
    }

    err = nvs_commit(nvs_handle);
    nvs_close(nvs_handle);

    if (err == ESP_OK)
    {
        ESP_LOGI(TAG, "✓ AP SSID saved to NVS: \"%s\"", ssid);
        strncpy(ap_ssid, ssid, sizeof(ap_ssid) - 1);
        ap_ssid[sizeof(ap_ssid) - 1] = '\0'; // Ensure null termination
    }
    else
    {
        ESP_LOGE(TAG, "Error committing AP SSID to NVS: %s", esp_err_to_name(err));
    }

    return err;
}

// Load AP SSID from NVS
static esp_err_t load_ap_ssid(void)
{
    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "NVS not available for AP SSID (using default): %s", esp_err_to_name(err));
        return err;
    }

    size_t ssid_len = sizeof(ap_ssid);
    err = nvs_get_str(nvs_handle, AP_SSID_KEY, ap_ssid, &ssid_len);
    if (err == ESP_OK)
    {
        ESP_LOGI(TAG, "✓ Loaded AP SSID from NVS: \"%s\"", ap_ssid);
    }
    else if (err == ESP_ERR_NVS_NOT_FOUND)
    {
        ESP_LOGI(TAG, "No AP SSID in NVS, using default: \"%s\"", ap_ssid);
    }
    else
    {
        ESP_LOGE(TAG, "Error loading AP SSID: %s", esp_err_to_name(err));
    }

    nvs_close(nvs_handle);
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

// Reconfigure AP SSID dynamically (without restarting device)
static esp_err_t reconfigure_ap_ssid(const char *new_ssid)
{
    if (!is_valid_ssid(new_ssid))
    {
        ESP_LOGE(TAG, "Cannot reconfigure with invalid SSID");
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(TAG, "Reconfiguring AP SSID from \"%s\" to \"%s\"...", ap_ssid, new_ssid);

    // Step 1: Save new SSID to NVS first (so it persists across reboot)
    esp_err_t err = save_ap_ssid(new_ssid);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to save new SSID to NVS: %s", esp_err_to_name(err));
        return err;
    }

    // Step 2: Stop WiFi
    ESP_LOGI(TAG, "Stopping WiFi...");
    err = esp_wifi_stop();
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to stop WiFi: %s", esp_err_to_name(err));
        return err;
    }

    // Give brief delay for WiFi to stop cleanly
    vTaskDelay(pdMS_TO_TICKS(100));

    // Step 3: Reconfigure AP with new SSID
    wifi_config_t ap_config = {0};
    strncpy((char *)ap_config.ap.ssid, new_ssid, sizeof(ap_config.ap.ssid));
    ap_config.ap.ssid_len = strlen(new_ssid);
    ap_config.ap.channel = MESH_CHANNEL;
    ap_config.ap.max_connection = 4;
    ap_config.ap.authmode = WIFI_AUTH_OPEN;
    ap_config.ap.pmf_cfg.required = false;

    err = esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to set AP config: %s", esp_err_to_name(err));
        return err;
    }
    ESP_LOGI(TAG, "✓ AP config updated with new SSID");

    // Step 4: Reconfigure STA (preserve existing router connection)
    wifi_config_t sta_config = {0};
    strncpy((char *)sta_config.sta.ssid, current_wifi_ssid, sizeof(sta_config.sta.ssid));
    strncpy((char *)sta_config.sta.password, current_wifi_pass, sizeof(sta_config.sta.password));
    sta_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    sta_config.sta.pmf_cfg.capable = true;
    sta_config.sta.pmf_cfg.required = false;

    err = esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to set STA config: %s", esp_err_to_name(err));
        return err;
    }
    ESP_LOGI(TAG, "✓ STA config preserved");

    // Step 5: Restart WiFi
    ESP_LOGI(TAG, "Restarting WiFi...");
    err = esp_wifi_start();
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to restart WiFi: %s", esp_err_to_name(err));
        return err;
    }

    // Step 6: Reconnect STA to router
    err = esp_wifi_connect();
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "WiFi reconnection may take a moment: %s", esp_err_to_name(err));
    }

    ESP_LOGI(TAG, "✓ AP SSID reconfigured successfully to \"%s\"", new_ssid);
    ESP_LOGI(TAG, "✓ Guests can now connect to: \"%s\"", new_ssid);

    return ESP_OK;
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
            bool is_admin_config = (strstr(rx_buffer, "POST /admin/configure") != NULL);
            bool is_admin_status = (strstr(rx_buffer, "GET /admin/status") != NULL);
            bool is_customer_status = (strstr(rx_buffer, "GET /status") != NULL);
            bool is_api_token = (strstr(rx_buffer, "POST /api/token") != NULL && strstr(rx_buffer, "POST /api/token/") == NULL);
            bool is_api_token_disable = (strstr(rx_buffer, "POST /api/token/disable") != NULL);
            bool is_api_token_info = (strstr(rx_buffer, "GET /api/token/info") != NULL);
            bool is_api_token_batch_info = (strstr(rx_buffer, "GET /api/token/batch_info") != NULL);
            bool is_api_token_extend = (strstr(rx_buffer, "POST /api/token/extend") != NULL);
            bool is_api_tokens_list = (strstr(rx_buffer, "GET /api/tokens/list") != NULL);
            bool is_api_tokens_purge = (strstr(rx_buffer, "POST /api/tokens/purge") != NULL);
            bool is_api_uptime = (strstr(rx_buffer, "GET /api/uptime") != NULL);
            bool is_api_health = (strstr(rx_buffer, "GET /api/health") != NULL);
            bool is_api_mac_blacklist = (strstr(rx_buffer, "POST /api/mac/blacklist") != NULL);
            bool is_api_mac_whitelist = (strstr(rx_buffer, "POST /api/mac/whitelist") != NULL);
            bool is_api_mac_remove = (strstr(rx_buffer, "POST /api/mac/remove") != NULL);
            bool is_api_mac_list = (strstr(rx_buffer, "GET /api/mac/list") != NULL);
            bool is_api_mac_clear = (strstr(rx_buffer, "POST /api/mac/clear") != NULL);
            bool is_admin_login = (strstr(rx_buffer, "POST /admin/login") != NULL);
            bool is_admin_logout = (strstr(rx_buffer, "POST /admin/logout") != NULL);
            bool is_admin_change_pass = (strstr(rx_buffer, "POST /admin/change_password") != NULL);
            bool is_admin_regen_key = (strstr(rx_buffer, "POST /admin/regenerate_key") != NULL);
            bool is_admin_generate_token = (strstr(rx_buffer, "POST /admin/generate_token") != NULL);
            bool is_admin_reset_tokens = (strstr(rx_buffer, "POST /admin/reset_tokens") != NULL);
            bool is_admin_set_ap_ssid = (strstr(rx_buffer, "POST /admin/set_ap_ssid") != NULL);
            bool is_admin_ota = (strstr(rx_buffer, "POST /admin/ota") != NULL);
            bool is_admin_page = ((strstr(rx_buffer, "GET /admin ") != NULL || strstr(rx_buffer, "GET /admin\r") != NULL || strstr(rx_buffer, "GET /admin\n") != NULL || strstr(rx_buffer, "GET /admin\t") != NULL) && !is_admin_status && !is_admin_config && !is_admin_login && !is_admin_logout && !is_admin_change_pass && !is_admin_regen_key && !is_admin_generate_token && !is_admin_reset_tokens && !is_admin_set_ap_ssid && !is_admin_ota);

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
                            else if (err == ESP_ERR_NO_MEM)
                            {
                                // Token limit reached (after cleanup attempt)
                                char error_response[256];
                                snprintf(error_response, sizeof(error_response),
                                         "HTTP/1.1 507 Insufficient Storage\r\n"
                                         "Content-Type: application/json\r\n"
                                         "Connection: close\r\n\r\n"
                                         "{\"success\":false,\"error\":\"Token limit reached (max %d active tokens)\",\"error_code\":\"TOKEN_LIMIT_REACHED\",\"max_tokens\":%d,\"current_tokens\":%d}",
                                         MAX_TOKENS, MAX_TOKENS, token_blob.token_count);
                                send(sock, error_response, strlen(error_response), 0);
                                ESP_LOGW(TAG, "API: Token creation denied - limit reached (%d/%d)", token_blob.token_count, MAX_TOKENS);
                            }
                            else if (err == ESP_ERR_INVALID_ARG)
                            {
                                // Invalid duration
                                char error_response[256];
                                snprintf(error_response, sizeof(error_response),
                                         "HTTP/1.1 400 Bad Request\r\n"
                                         "Content-Type: application/json\r\n"
                                         "Connection: close\r\n\r\n"
                                         "{\"success\":false,\"error\":\"Duration must be between %d and %d minutes\",\"error_code\":\"INVALID_DURATION\"}",
                                         TOKEN_MIN_DURATION_MINUTES, TOKEN_MAX_DURATION_MINUTES);
                                send(sock, error_response, strlen(error_response), 0);
                                ESP_LOGW(TAG, "API: Token creation denied - invalid duration %lu", duration);
                            }
                            else
                            {
                                // Other errors (NVS issues, etc.)
                                char error_response[256];
                                snprintf(error_response, sizeof(error_response),
                                         "HTTP/1.1 500 Internal Server Error\r\n"
                                         "Content-Type: application/json\r\n"
                                         "Connection: close\r\n\r\n"
                                         "{\"success\":false,\"error\":\"Internal error creating token\",\"error_code\":\"INTERNAL_ERROR\"}");
                                send(sock, error_response, strlen(error_response), 0);
                                ESP_LOGE(TAG, "API: Token creation failed with error: %s", esp_err_to_name(err));
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
                            for (int i = 0; i < token_blob.token_count; i++)
                            {
                                if (token_blob.tokens[i].active &&
                                    strcmp(token_blob.tokens[i].token, token_to_disable) == 0)
                                {
                                    token_blob.tokens[i].active = false;

                                    // Compact array immediately by shifting remaining tokens
                                    for (int j = i; j < token_blob.token_count - 1; j++)
                                    {
                                        token_blob.tokens[j] = token_blob.tokens[j + 1];
                                    }
                                    token_blob.token_count--;
                                    found = true;

                                    // Save updated blob to NVS
                                    save_tokens_blob_to_nvs();

                                    const char *success_response =
                                        "HTTP/1.1 200 OK\r\n"
                                        "Content-Type: application/json\r\n"
                                        "Connection: close\r\n\r\n"
                                        "{\"success\":true,\"message\":\"Token disabled successfully\"}";
                                    send(sock, success_response, strlen(success_response), 0);
                                    ESP_LOGI(TAG, "API: Token %s disabled via API (count now: %d)",
                                             token_to_disable, token_blob.token_count);
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
                            for (int i = 0; i < token_blob.token_count; i++)
                            {
                                if (token_blob.tokens[i].active &&
                                    strcmp(token_blob.tokens[i].token, token_to_query) == 0)
                                {
                                    found = true;
                                    time_t now = time(NULL);
                                    // expires_at is only meaningful for used tokens
                                    time_t expires_at = token_blob.tokens[i].first_use > 0
                                                            ? token_blob.tokens[i].first_use + (token_blob.tokens[i].duration_minutes * 60)
                                                            : 0;
                                    bool is_expired = (token_blob.tokens[i].first_use > 0 && now > expires_at);
                                    bool is_used = (token_blob.tokens[i].first_use > 0);
                                    int64_t remaining_seconds = is_used && !is_expired
                                                                    ? (expires_at - now)
                                                                    : 0;

                                    // Sanitize string fields to prevent invalid JSON
                                    char safe_hostname[64];
                                    char safe_device_type[32];
                                    sanitize_string(token_blob.tokens[i].hostname, safe_hostname, sizeof(safe_hostname));
                                    sanitize_string(token_blob.tokens[i].device_type, safe_device_type, sizeof(safe_device_type));

                                    char response[2048]; // Increased buffer for device info
                                    int offset = snprintf(response, sizeof(response),
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
                                                          "\"max_devices\":%d,"
                                                          "\"hostname\":\"%s\","
                                                          "\"device_type\":\"%s\","
                                                          "\"first_seen\":%lld,"
                                                          "\"last_seen\":%lld,"
                                                          "\"devices\":[",
                                                          token_blob.tokens[i].token,
                                                          is_expired ? "expired" : (is_used ? "active" : "unused"),
                                                          (long long)token_blob.tokens[i].created,
                                                          (long long)token_blob.tokens[i].first_use,
                                                          token_blob.tokens[i].duration_minutes,
                                                          (long long)expires_at,
                                                          remaining_seconds,
                                                          token_blob.tokens[i].bandwidth_down_mb,
                                                          token_blob.tokens[i].bandwidth_up_mb,
                                                          token_blob.tokens[i].bandwidth_used_down,
                                                          token_blob.tokens[i].bandwidth_used_up,
                                                          token_blob.tokens[i].usage_count,
                                                          token_blob.tokens[i].device_count,
                                                          MAX_DEVICES_PER_TOKEN,
                                                          safe_hostname,
                                                          safe_device_type,
                                                          (long long)token_blob.tokens[i].first_seen,
                                                          (long long)token_blob.tokens[i].last_seen);

                                    // Add device information for each MAC
                                    for (int mac_idx = 0; mac_idx < token_blob.tokens[i].device_count && mac_idx < MAX_DEVICES_PER_TOKEN; mac_idx++)
                                    {
                                        if (mac_idx > 0)
                                        {
                                            offset += snprintf(response + offset, sizeof(response) - offset, ",");
                                        }

                                        // Check if device is currently online
                                        uint32_t current_ip = 0;
                                        bool is_online = check_device_online(token_blob.tokens[i].client_macs[mac_idx], &current_ip);

                                        offset += snprintf(response + offset, sizeof(response) - offset,
                                                           "{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"online\":%s",
                                                           token_blob.tokens[i].client_macs[mac_idx][0],
                                                           token_blob.tokens[i].client_macs[mac_idx][1],
                                                           token_blob.tokens[i].client_macs[mac_idx][2],
                                                           token_blob.tokens[i].client_macs[mac_idx][3],
                                                           token_blob.tokens[i].client_macs[mac_idx][4],
                                                           token_blob.tokens[i].client_macs[mac_idx][5],
                                                           is_online ? "true" : "false");

                                        if (is_online && current_ip != 0)
                                        {
                                            char ip_str[16];
                                            inet_ntop(AF_INET, &current_ip, ip_str, sizeof(ip_str));
                                            offset += snprintf(response + offset, sizeof(response) - offset,
                                                               ",\"current_ip\":\"%s\"", ip_str);
                                        }

                                        offset += snprintf(response + offset, sizeof(response) - offset, "}");
                                    }

                                    offset += snprintf(response + offset, sizeof(response) - offset, "]}");
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

            // Handle Token Batch Info API endpoint
            if (is_api_token_batch_info)
            {
                REJECT_LOCAL_AP_REQUEST(sock, source_addr);

                // Parse query string: /api/token/batch_info?api_key=XXX&tokens=token1,token2,token3
                char received_key[API_KEY_LENGTH + 1] = {0};
                char tokens_param[4096] = {0}; // Large buffer for multiple tokens

                char *query_start = strstr(rx_buffer, "GET /api/token/batch_info?");
                if (query_start)
                {
                    query_start += 26; // skip "GET /api/token/batch_info?"
                    char *key_start = strstr(query_start, "api_key=");
                    char *tokens_start = strstr(query_start, "tokens=");

                    if (key_start && tokens_start)
                    {
                        key_start += 8;
                        sscanf(key_start, "%32[^&\r\n ]", received_key);

                        tokens_start += 7;
                        sscanf(tokens_start, "%4095[^&\r\n ]", tokens_param);

                        // Validate API key
                        if (strcmp(received_key, api_key) == 0)
                        {
// Parse tokens from comma-separated list
#define MAX_BATCH_TOKENS 50
                            char *token_list[MAX_BATCH_TOKENS];
                            int token_count = 0;

                            char *token_ptr = tokens_param;
                            char *comma_pos;

                            while ((comma_pos = strchr(token_ptr, ',')) != NULL && token_count < MAX_BATCH_TOKENS)
                            {
                                *comma_pos = '\0';
                                token_list[token_count++] = token_ptr;
                                token_ptr = comma_pos + 1;
                            }

                            // Add the last token (or only token if no commas)
                            if (token_count < MAX_BATCH_TOKENS && *token_ptr != '\0')
                            {
                                token_list[token_count++] = token_ptr;
                            }

                            if (token_count == 0)
                            {
                                const char *error_response =
                                    "HTTP/1.1 400 Bad Request\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Connection: close\r\n\r\n"
                                    "{\"success\":false,\"error\":\"No tokens specified\",\"error_code\":\"NO_TOKENS_SPECIFIED\"}";
                                send(sock, error_response, strlen(error_response), 0);
                                close(sock);
                                continue;
                            }

                            if (token_count > MAX_BATCH_TOKENS)
                            {
                                char error_response[256];
                                snprintf(error_response, sizeof(error_response),
                                         "HTTP/1.1 400 Bad Request\r\n"
                                         "Content-Type: application/json\r\n"
                                         "Connection: close\r\n\r\n"
                                         "{\"success\":false,\"error\":\"Too many tokens requested (max %d)\",\"error_code\":\"TOO_MANY_TOKENS\",\"max_tokens\":%d,\"requested\":%d}",
                                         MAX_BATCH_TOKENS, MAX_BATCH_TOKENS, token_count);
                                send(sock, error_response, strlen(error_response), 0);
                                close(sock);
                                continue;
                            }

                            // Build response with token info array
                            char response[8192]; // Large buffer for multiple tokens
                            int offset = snprintf(response, sizeof(response),
                                                  "HTTP/1.1 200 OK\r\n"
                                                  "Content-Type: application/json\r\n"
                                                  "Connection: close\r\n\r\n"
                                                  "{\"success\":true,\"tokens\":[");

                            int tokens_found = 0;
                            time_t now = time(NULL);

                            for (int req_idx = 0; req_idx < token_count; req_idx++)
                            {
                                char *requested_token = token_list[req_idx];

                                // Find token in blob
                                bool found = false;
                                for (int i = 0; i < token_blob.token_count && !found; i++)
                                {
                                    if (token_blob.tokens[i].active &&
                                        strcmp(token_blob.tokens[i].token, requested_token) == 0)
                                    {
                                        found = true;

                                        if (tokens_found > 0)
                                        {
                                            offset += snprintf(response + offset, sizeof(response) - offset, ",");
                                        }
                                        tokens_found++;

                                        // Calculate expiration info
                                        time_t expires_at = token_blob.tokens[i].first_use > 0
                                                                ? token_blob.tokens[i].first_use + (token_blob.tokens[i].duration_minutes * 60)
                                                                : 0;
                                        bool is_expired = (token_blob.tokens[i].first_use > 0 && now > expires_at);
                                        bool is_used = (token_blob.tokens[i].first_use > 0);
                                        int64_t remaining_seconds = is_used && !is_expired ? (expires_at - now) : 0;

                                        offset += snprintf(response + offset, sizeof(response) - offset,
                                                           "{\"token\":\"%s\",\"status\":\"%s\",\"created\":%lld,\"first_use\":%lld,"
                                                           "\"duration_minutes\":%lu,\"expires_at\":%lld,\"remaining_seconds\":%lld,"
                                                           "\"bandwidth_down_mb\":%lu,\"bandwidth_up_mb\":%lu,"
                                                           "\"bandwidth_used_down_mb\":%lu,\"bandwidth_used_up_mb\":%lu,"
                                                           "\"usage_count\":%lu,\"device_count\":%u,\"max_devices\":%d,\"client_macs\":[",
                                                           token_blob.tokens[i].token,
                                                           is_expired ? "expired" : (is_used ? "active" : "unused"),
                                                           (long long)token_blob.tokens[i].created,
                                                           (long long)token_blob.tokens[i].first_use,
                                                           token_blob.tokens[i].duration_minutes,
                                                           (long long)expires_at,
                                                           remaining_seconds,
                                                           token_blob.tokens[i].bandwidth_down_mb,
                                                           token_blob.tokens[i].bandwidth_up_mb,
                                                           token_blob.tokens[i].bandwidth_used_down,
                                                           token_blob.tokens[i].bandwidth_used_up,
                                                           token_blob.tokens[i].usage_count,
                                                           token_blob.tokens[i].device_count,
                                                           MAX_DEVICES_PER_TOKEN);

                                        // Add MAC addresses
                                        for (int mac_idx = 0; mac_idx < token_blob.tokens[i].device_count && mac_idx < MAX_DEVICES_PER_TOKEN; mac_idx++)
                                        {
                                            if (mac_idx > 0)
                                            {
                                                offset += snprintf(response + offset, sizeof(response) - offset, ",");
                                            }
                                            offset += snprintf(response + offset, sizeof(response) - offset,
                                                               "\"%02X:%02X:%02X:%02X:%02X:%02X\"",
                                                               token_blob.tokens[i].client_macs[mac_idx][0],
                                                               token_blob.tokens[i].client_macs[mac_idx][1],
                                                               token_blob.tokens[i].client_macs[mac_idx][2],
                                                               token_blob.tokens[i].client_macs[mac_idx][3],
                                                               token_blob.tokens[i].client_macs[mac_idx][4],
                                                               token_blob.tokens[i].client_macs[mac_idx][5]);
                                        }

                                        offset += snprintf(response + offset, sizeof(response) - offset, "]}");
                                    }
                                }
                            }

                            offset += snprintf(response + offset, sizeof(response) - offset, "],\"total_requested\":%d,\"total_found\":%d}", token_count, tokens_found);
                            send(sock, response, strlen(response), 0);
                            ESP_LOGI(TAG, "API: Batch token info requested %d tokens, found %d", token_count, tokens_found);
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
                            "{\"success\":false,\"error\":\"Missing required parameters (api_key, tokens)\"}";
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
                            for (int i = 0; i < token_blob.token_count; i++)
                            {
                                if (token_blob.tokens[i].active &&
                                    strcmp(token_blob.tokens[i].token, token_to_extend) == 0)
                                {
                                    found = true;

                                    // Reset data usage counters
                                    token_blob.tokens[i].bandwidth_used_down = 0;
                                    token_blob.tokens[i].bandwidth_used_up = 0;

                                    // Reset time - set first_use to now to restart the duration
                                    token_blob.tokens[i].first_use = time(NULL);

                                    // Reset usage count
                                    token_blob.tokens[i].usage_count = 0;

                                    save_tokens_blob_to_nvs(); // Persist to NVS

                                    time_t new_expires = token_blob.tokens[i].first_use +
                                                         (token_blob.tokens[i].duration_minutes * 60);

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
                                             token_blob.tokens[i].token,
                                             token_blob.tokens[i].duration_minutes,
                                             token_blob.tokens[i].duration_minutes,
                                             (long long)new_expires,
                                             token_blob.tokens[i].bandwidth_down_mb,
                                             token_blob.tokens[i].bandwidth_up_mb);
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
                int active_count = token_blob.token_count;

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

                // Parse query string: /api/tokens/list?api_key=XXX&status=unused&min_age_minutes=60&...
                char *query_start = strstr(rx_buffer, "GET /api/tokens/list?");
                if (query_start != NULL)
                {
                    query_start += 21; // skip "GET /api/tokens/list?"
                    char received_key[API_KEY_LENGTH + 1] = {0};
                    char status_filter[16] = "all"; // Default: return all tokens
                    uint32_t min_age_minutes = 0;
                    uint32_t max_age_minutes = 0;
                    bool used_only = false;
                    bool unused_only = false;

                    // Parse all query parameters
                    char *key_start = strstr(query_start, "api_key=");
                    char *status_start = strstr(query_start, "status=");
                    char *min_age_start = strstr(query_start, "min_age_minutes=");
                    char *max_age_start = strstr(query_start, "max_age_minutes=");
                    char *used_start = strstr(query_start, "used_only=");
                    char *unused_start = strstr(query_start, "unused_only=");

                    if (key_start)
                    {
                        key_start += 8;
                        sscanf(key_start, "%32[^& \r\n]", received_key);

                        // Parse optional filter parameters
                        if (status_start)
                        {
                            status_start += 7;
                            sscanf(status_start, "%15[^& \r\n]", status_filter);
                        }
                        if (min_age_start)
                        {
                            min_age_start += 15;
                            sscanf(min_age_start, "%lu", &min_age_minutes);
                        }
                        if (max_age_start)
                        {
                            max_age_start += 15;
                            sscanf(max_age_start, "%lu", &max_age_minutes);
                        }
                        if (used_start)
                        {
                            used_start += 10;
                            used_only = (strstr(used_start, "true") != NULL);
                        }
                        if (unused_start)
                        {
                            unused_start += 12;
                            unused_only = (strstr(unused_start, "true") != NULL);
                        }

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
                                                  token_blob.token_count); // This will be updated later

                            time_t now = time(NULL);
                            int filtered_count = 0;
                            for (int i = 0; i < token_blob.token_count; i++)
                            {
                                if (token_blob.tokens[i].active)
                                {
                                    time_t expires_at = token_blob.tokens[i].first_use > 0
                                                            ? token_blob.tokens[i].first_use + (token_blob.tokens[i].duration_minutes * 60)
                                                            : 0;

                                    int remaining_sec = (int)difftime(expires_at, now);
                                    const char *status = (token_blob.tokens[i].first_use == 0) ? "unused"
                                                         : (remaining_sec > 0)                 ? "active"
                                                                                               : "expired";

                                    // Apply filters
                                    bool include_token = true;

                                    // Status filter
                                    if (strcmp(status_filter, "all") != 0 && strcmp(status, status_filter) != 0)
                                    {
                                        include_token = false;
                                    }

                                    // Used/unused filters
                                    if (used_only && token_blob.tokens[i].first_use == 0)
                                    {
                                        include_token = false;
                                    }
                                    if (unused_only && token_blob.tokens[i].first_use != 0)
                                    {
                                        include_token = false;
                                    }

                                    // Age filters (based on creation time)
                                    if (min_age_minutes > 0 || max_age_minutes > 0)
                                    {
                                        time_t token_age_minutes = (now - token_blob.tokens[i].created) / 60;
                                        if (min_age_minutes > 0 && token_age_minutes < min_age_minutes)
                                        {
                                            include_token = false;
                                        }
                                        if (max_age_minutes > 0 && token_age_minutes > max_age_minutes)
                                        {
                                            include_token = false;
                                        }
                                    }

                                    if (!include_token)
                                    {
                                        continue; // Skip this token
                                    }

                                    filtered_count++; // Count filtered tokens

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
                                                       "\"usage_count\":%lu,"
                                                       "\"device_count\":%u,"
                                                       "\"client_macs\":[",
                                                       (i > 0) ? "," : "",
                                                       token_blob.tokens[i].token,
                                                       status,
                                                       token_blob.tokens[i].duration_minutes,
                                                       (long long)token_blob.tokens[i].first_use,
                                                       (long long)expires_at,
                                                       remaining_sec > 0 ? remaining_sec : 0,
                                                       token_blob.tokens[i].bandwidth_down_mb,
                                                       token_blob.tokens[i].bandwidth_up_mb,
                                                       token_blob.tokens[i].bandwidth_used_down,
                                                       token_blob.tokens[i].bandwidth_used_up,
                                                       token_blob.tokens[i].usage_count,
                                                       token_blob.tokens[i].device_count);

                                    // Add MAC addresses for this token
                                    for (int mac_idx = 0; mac_idx < token_blob.tokens[i].device_count && mac_idx < MAX_DEVICES_PER_TOKEN; mac_idx++)
                                    {
                                        if (mac_idx > 0)
                                        {
                                            offset += snprintf(response + offset, 8192 - offset, ",");
                                        }
                                        offset += snprintf(response + offset, 8192 - offset,
                                                           "\"%02X:%02X:%02X:%02X:%02X:%02X\"",
                                                           token_blob.tokens[i].client_macs[mac_idx][0],
                                                           token_blob.tokens[i].client_macs[mac_idx][1],
                                                           token_blob.tokens[i].client_macs[mac_idx][2],
                                                           token_blob.tokens[i].client_macs[mac_idx][3],
                                                           token_blob.tokens[i].client_macs[mac_idx][4],
                                                           token_blob.tokens[i].client_macs[mac_idx][5]);
                                    }

                                    offset += snprintf(response + offset, 8192 - offset, "]}");

                                    if (offset >= 7800)
                                    { // Leave room for closing
                                        break;
                                    }
                                }
                            }

                            // Update the count in the JSON response to reflect filtered count
                            char count_str[16];
                            snprintf(count_str, sizeof(count_str), "%d", filtered_count);
                            char *count_pos = strstr(response, "\"count\":");
                            if (count_pos)
                            {
                                count_pos += 8; // Skip "count":
                                char *comma_pos = strchr(count_pos, ',');
                                if (comma_pos)
                                {
                                    // Replace the old count with filtered count
                                    memmove(count_pos, count_str, strlen(count_str));
                                    memmove(count_pos + strlen(count_str), comma_pos, strlen(comma_pos) + 1);
                                }
                            }

                            snprintf(response + offset, 8192 - offset, "]}");
                            send(sock, response, strlen(response), 0);
                            free(response);
                            ESP_LOGI(TAG, "API: Listed %d filtered tokens via API (from %d total)", filtered_count, token_blob.token_count);
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

            // Handle Tokens Purge API endpoint
            if (is_api_tokens_purge)
            {
                REJECT_LOCAL_AP_REQUEST(sock, source_addr);

                char *body = strstr(rx_buffer, "\r\n\r\n");
                if (body != NULL)
                {
                    body += 4;
                    char received_key[API_KEY_LENGTH + 1] = {0};
                    bool unused_only = false;
                    uint32_t max_age_minutes = 0;
                    bool expired_only = false;

                    // Parse: api_key=XXX&unused_only=true&max_age_minutes=XXX&expired_only=true
                    char *key_start = strstr(body, "api_key=");
                    char *unused_start = strstr(body, "unused_only=");
                    char *age_start = strstr(body, "max_age_minutes=");
                    char *expired_start = strstr(body, "expired_only=");

                    if (key_start)
                    {
                        key_start += 8;
                        sscanf(key_start, "%32[^&\r\n]", received_key);

                        // Parse optional parameters
                        if (unused_start)
                        {
                            unused_start += 12;
                            unused_only = (strstr(unused_start, "true") != NULL);
                        }
                        if (age_start)
                        {
                            age_start += 15;
                            sscanf(age_start, "%lu", &max_age_minutes);
                        }
                        if (expired_start)
                        {
                            expired_start += 13;
                            expired_only = (strstr(expired_start, "true") != NULL);
                        }

                        // Validate API key
                        if (strcmp(received_key, api_key) == 0)
                        {
                            time_t now = time(NULL);
                            int purged_count = 0;
                            char purged_tokens[512] = {0}; // Store list of purged tokens

                            // Iterate through all tokens and apply purge criteria
                            for (int i = token_blob.token_count - 1; i >= 0; i--)
                            {
                                if (!token_blob.tokens[i].active)
                                    continue;

                                bool should_purge = false;
                                const char *reason = "";

                                // Check expired tokens
                                if (expired_only)
                                {
                                    if (token_blob.tokens[i].first_use > 0)
                                    {
                                        time_t expires_at = token_blob.tokens[i].first_use + (token_blob.tokens[i].duration_minutes * 60);
                                        if (expires_at <= now)
                                        {
                                            should_purge = true;
                                            reason = "expired";
                                        }
                                    }
                                }
                                // Check unused tokens by age
                                else if (unused_only && max_age_minutes > 0)
                                {
                                    time_t token_age_minutes = (now - token_blob.tokens[i].created) / 60;
                                    if (token_blob.tokens[i].first_use == 0 && token_age_minutes >= max_age_minutes)
                                    {
                                        should_purge = true;
                                        reason = "unused_old";
                                    }
                                }
                                // Check unused tokens (any age)
                                else if (unused_only && token_blob.tokens[i].first_use == 0)
                                {
                                    should_purge = true;
                                    reason = "unused";
                                }
                                // Check old tokens (used or unused) by age
                                else if (max_age_minutes > 0)
                                {
                                    time_t token_age_minutes = (now - token_blob.tokens[i].created) / 60;
                                    if (token_age_minutes >= max_age_minutes)
                                    {
                                        should_purge = true;
                                        reason = "old";
                                    }
                                }

                                if (should_purge)
                                {
                                    // Add to purged list for response
                                    if (purged_count > 0)
                                        strncat(purged_tokens, ",", sizeof(purged_tokens) - strlen(purged_tokens) - 1);
                                    strncat(purged_tokens, token_blob.tokens[i].token, sizeof(purged_tokens) - strlen(purged_tokens) - 1);

                                    // Disable token (same logic as disable endpoint)
                                    token_blob.tokens[i].active = false;

                                    // Compact array by shifting remaining tokens
                                    for (int j = i; j < token_blob.token_count - 1; j++)
                                    {
                                        token_blob.tokens[j] = token_blob.tokens[j + 1];
                                    }
                                    token_blob.token_count--;

                                    purged_count++;
                                    ESP_LOGI(TAG, "API: Token %s purged (%s)", token_blob.tokens[i].token, reason);
                                }
                            }

                            // Save updated blob to NVS if any tokens were purged
                            if (purged_count > 0)
                            {
                                save_tokens_blob_to_nvs();
                            }

                            // Build response
                            char response_buffer[1024];
                            snprintf(response_buffer, sizeof(response_buffer),
                                     "HTTP/1.1 200 OK\r\n"
                                     "Content-Type: application/json\r\n"
                                     "Connection: close\r\n\r\n"
                                     "{\"success\":true,\"purged_count\":%d,\"purged_tokens\":[%s]}",
                                     purged_count,
                                     purged_count > 0 ? purged_tokens : "");

                            send(sock, response_buffer, strlen(response_buffer), 0);
                            ESP_LOGI(TAG, "API: Purged %d tokens via API (count now: %d)", purged_count, token_blob.token_count);
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

            // Handle POST /api/mac/blacklist - Add MAC(s) from token to blacklist
            if (is_api_mac_blacklist)
            {
                REJECT_LOCAL_AP_REQUEST(sock, source_addr);

                char *body = strstr(rx_buffer, "\r\n\r\n");
                if (body != NULL)
                {
                    body += 4;
                    char received_key[API_KEY_LENGTH + 1] = {0};
                    char token_str[TOKEN_LENGTH + 1] = {0};
                    char reason[32] = "Blocked by admin";

                    // Parse parameters
                    char *key_start = strstr(body, "api_key=");
                    char *token_start = strstr(body, "token=");
                    char *reason_start = strstr(body, "reason=");

                    if (key_start && token_start)
                    {
                        key_start += 8;
                        sscanf(key_start, "%32[^&\r\n]", received_key);

                        token_start += 6;
                        sscanf(token_start, "%8[^&\r\n]", token_str);

                        if (reason_start)
                        {
                            reason_start += 7;
                            sscanf(reason_start, "%31[^&\r\n]", reason);
                        }

                        if (strcmp(received_key, api_key) == 0)
                        {
                            // Find token and extract MACs
                            bool found = false;
                            int macs_added = 0;

                            for (int i = 0; i < token_blob.token_count; i++)
                            {
                                if (token_blob.tokens[i].active && strcmp(token_blob.tokens[i].token, token_str) == 0)
                                {
                                    found = true;

                                    // Add all client MACs from this token to blacklist
                                    for (int j = 0; j < token_blob.tokens[i].device_count; j++)
                                    {
                                        if (add_to_blacklist(token_blob.tokens[i].client_macs[j], token_str, reason) == ESP_OK)
                                        {
                                            macs_added++;
                                        }
                                    }
                                    break;
                                }
                            }

                            if (found && macs_added > 0)
                            {
                                // Save to NVS
                                save_blacklist_to_nvs();

                                char response_buffer[512];
                                snprintf(response_buffer, sizeof(response_buffer),
                                         "HTTP/1.1 200 OK\r\n"
                                         "Content-Type: application/json\r\n"
                                         "Connection: close\r\n\r\n"
                                         "{\"success\":true,\"message\":\"Added %d MAC(s) to blacklist\",\"count\":%d}",
                                         macs_added, macs_added);
                                send(sock, response_buffer, strlen(response_buffer), 0);
                                ESP_LOGI(TAG, "API: Added %d MAC(s) from token %s to blacklist", macs_added, token_str);
                            }
                            else if (found && macs_added == 0)
                            {
                                const char *error_response =
                                    "HTTP/1.1 400 Bad Request\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Connection: close\r\n\r\n"
                                    "{\"success\":false,\"error\":\"Token has no client MACs to blacklist\"}";
                                send(sock, error_response, strlen(error_response), 0);
                            }
                            else
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

            // Handle POST /api/mac/whitelist - Add MAC(s) from token to whitelist (VIP bypass)
            if (is_api_mac_whitelist)
            {
                REJECT_LOCAL_AP_REQUEST(sock, source_addr);

                char *body = strstr(rx_buffer, "\r\n\r\n");
                if (body != NULL)
                {
                    body += 4;
                    char received_key[API_KEY_LENGTH + 1] = {0};
                    char token_str[TOKEN_LENGTH + 1] = {0};
                    char note[32] = "VIP access";

                    // Parse parameters
                    char *key_start = strstr(body, "api_key=");
                    char *token_start = strstr(body, "token=");
                    char *note_start = strstr(body, "note=");

                    if (key_start && token_start)
                    {
                        key_start += 8;
                        sscanf(key_start, "%32[^&\r\n]", received_key);

                        token_start += 6;
                        sscanf(token_start, "%8[^&\r\n]", token_str);

                        if (note_start)
                        {
                            note_start += 5;
                            sscanf(note_start, "%31[^&\r\n]", note);
                        }

                        if (strcmp(received_key, api_key) == 0)
                        {
                            // Find token and extract MACs
                            bool found = false;
                            int macs_added = 0;

                            for (int i = 0; i < token_blob.token_count; i++)
                            {
                                if (token_blob.tokens[i].active && strcmp(token_blob.tokens[i].token, token_str) == 0)
                                {
                                    found = true;

                                    // Add all client MACs from this token to whitelist
                                    for (int j = 0; j < token_blob.tokens[i].device_count; j++)
                                    {
                                        if (add_to_whitelist(token_blob.tokens[i].client_macs[j], token_str, note) == ESP_OK)
                                        {
                                            macs_added++;
                                        }
                                    }
                                    break;
                                }
                            }

                            if (found && macs_added > 0)
                            {
                                // Save to NVS
                                save_whitelist_to_nvs();

                                char response_buffer[512];
                                snprintf(response_buffer, sizeof(response_buffer),
                                         "HTTP/1.1 200 OK\r\n"
                                         "Content-Type: application/json\r\n"
                                         "Connection: close\r\n\r\n"
                                         "{\"success\":true,\"message\":\"Added %d MAC(s) to whitelist (VIP bypass)\",\"count\":%d}",
                                         macs_added, macs_added);
                                send(sock, response_buffer, strlen(response_buffer), 0);
                                ESP_LOGI(TAG, "API: Added %d MAC(s) from token %s to whitelist", macs_added, token_str);
                            }
                            else if (found && macs_added == 0)
                            {
                                const char *error_response =
                                    "HTTP/1.1 400 Bad Request\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Connection: close\r\n\r\n"
                                    "{\"success\":false,\"error\":\"Token has no client MACs to whitelist\"}";
                                send(sock, error_response, strlen(error_response), 0);
                            }
                            else
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

            // Handle GET /api/mac/list - List blacklist and/or whitelist entries
            if (is_api_mac_list)
            {
                REJECT_LOCAL_AP_REQUEST(sock, source_addr);

                // Parse query string for API key and optional list parameter
                char received_key[API_KEY_LENGTH + 1] = {0};
                char list_param[16] = "both"; // Default: return both lists
                char *query_start = strstr(rx_buffer, "GET /api/mac/list?");

                if (query_start)
                {
                    query_start += 18; // skip "GET /api/mac/list?"
                    char *key_start = strstr(query_start, "api_key=");
                    char *list_start = strstr(query_start, "list=");

                    if (key_start)
                    {
                        key_start += 8;
                        sscanf(key_start, "%32[^&\r\n ]", received_key);

                        if (list_start)
                        {
                            list_start += 5;
                            sscanf(list_start, "%15[^&\r\n ]", list_param);
                        }

                        if (strcmp(received_key, api_key) == 0)
                        {
                            // Validate list parameter
                            bool return_blacklist = (strcmp(list_param, "blacklist") == 0 || strcmp(list_param, "both") == 0);
                            bool return_whitelist = (strcmp(list_param, "whitelist") == 0 || strcmp(list_param, "both") == 0);

                            if (!return_blacklist && !return_whitelist)
                            {
                                const char *error_response =
                                    "HTTP/1.1 400 Bad Request\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Connection: close\r\n\r\n"
                                    "{\"success\":false,\"error\":\"Invalid list parameter. Use 'blacklist', 'whitelist', or 'both'\"}";
                                send(sock, error_response, strlen(error_response), 0);
                                close(sock);
                                continue;
                            }

                            // Build JSON response
                            char *response_buffer = (char *)malloc(8192);
                            if (response_buffer)
                            {
                                int len = snprintf(response_buffer, 8192,
                                                   "HTTP/1.1 200 OK\r\n"
                                                   "Content-Type: application/json\r\n"
                                                   "Connection: close\r\n\r\n"
                                                   "{\"success\":true");

                                // Add blacklist entries if requested
                                if (return_blacklist)
                                {
                                    len += snprintf(response_buffer + len, 8192 - len, ",\"blacklist\":[");

                                    bool first = true;
                                    for (int i = 0; i < blacklist_blob.entry_count && i < MAX_BLACKLIST_ENTRIES; i++)
                                    {
                                        if (blacklist_blob.entries[i].active)
                                        {
                                            if (!first)
                                                len += snprintf(response_buffer + len, 8192 - len, ",");
                                            first = false;

                                            char mac_str[18];
                                            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                                                     blacklist_blob.entries[i].mac[0], blacklist_blob.entries[i].mac[1], blacklist_blob.entries[i].mac[2],
                                                     blacklist_blob.entries[i].mac[3], blacklist_blob.entries[i].mac[4], blacklist_blob.entries[i].mac[5]);

                                            len += snprintf(response_buffer + len, 8192 - len,
                                                            "{\"mac\":\"%s\",\"token\":\"%s\",\"reason\":\"%s\",\"added\":%ld}",
                                                            mac_str, blacklist_blob.entries[i].token, blacklist_blob.entries[i].reason, (long)blacklist_blob.entries[i].added);
                                        }
                                    }

                                    len += snprintf(response_buffer + len, 8192 - len, "]");
                                }

                                // Add whitelist entries if requested
                                if (return_whitelist)
                                {
                                    len += snprintf(response_buffer + len, 8192 - len, ",\"whitelist\":[");

                                    bool first = true;
                                    for (int i = 0; i < whitelist_blob.entry_count && i < MAX_WHITELIST_ENTRIES; i++)
                                    {
                                        if (whitelist_blob.entries[i].active)
                                        {
                                            if (!first)
                                                len += snprintf(response_buffer + len, 8192 - len, ",");
                                            first = false;

                                            char mac_str[18];
                                            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                                                     whitelist_blob.entries[i].mac[0], whitelist_blob.entries[i].mac[1], whitelist_blob.entries[i].mac[2],
                                                     whitelist_blob.entries[i].mac[3], whitelist_blob.entries[i].mac[4], whitelist_blob.entries[i].mac[5]);

                                            len += snprintf(response_buffer + len, 8192 - len,
                                                            "{\"mac\":\"%s\",\"token\":\"%s\",\"note\":\"%s\",\"added\":%ld}",
                                                            mac_str, whitelist_blob.entries[i].token, whitelist_blob.entries[i].note, (long)whitelist_blob.entries[i].added);
                                        }
                                    }

                                    len += snprintf(response_buffer + len, 8192 - len, "]");
                                }

                                // Add counts
                                len += snprintf(response_buffer + len, 8192 - len,
                                                ",\"blacklist_count\":%d,\"whitelist_count\":%d,\"requested_list\":\"%s\"}",
                                                blacklist_blob.entry_count, whitelist_blob.entry_count, list_param);

                                send(sock, response_buffer, len, 0);
                                free(response_buffer);
                                ESP_LOGI(TAG, "API: Listed MAC filters (list:%s, BL:%d, WL:%d)", list_param, blacklist_blob.entry_count, whitelist_blob.entry_count);
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
                            "{\"success\":false,\"error\":\"Missing required parameter: api_key\"}";
                        send(sock, error_response, strlen(error_response), 0);
                    }
                }
                close(sock);
                continue;
            }

            // Handle POST /api/mac/remove - Remove MAC from blacklist/whitelist
            if (is_api_mac_remove)
            {
                REJECT_LOCAL_AP_REQUEST(sock, source_addr);

                char *body = strstr(rx_buffer, "\r\n\r\n");
                if (body != NULL)
                {
                    body += 4;
                    char received_key[API_KEY_LENGTH + 1] = {0};
                    char mac_str[18] = {0};
                    char list_type[16] = "both"; // Default: remove from both lists

                    // Parse parameters
                    char *key_start = strstr(body, "api_key=");
                    char *mac_start = strstr(body, "mac=");
                    char *list_start = strstr(body, "list=");

                    if (key_start && mac_start)
                    {
                        key_start += 8;
                        sscanf(key_start, "%32[^&\r\n]", received_key);

                        mac_start += 4;
                        sscanf(mac_start, "%17[^&\r\n]", mac_str);

                        if (list_start)
                        {
                            list_start += 5;
                            sscanf(list_start, "%15[^&\r\n]", list_type);
                        }

                        if (strcmp(received_key, api_key) == 0)
                        {
                            // Parse MAC address
                            uint8_t mac[6];
                            int parsed = sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                                                &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

                            if (parsed == 6)
                            {
                                bool removed = false;

                                // Remove from blacklist if requested
                                if (strcmp(list_type, "blacklist") == 0 || strcmp(list_type, "both") == 0)
                                {
                                    if (remove_from_blacklist(mac) == ESP_OK)
                                    {
                                        save_blacklist_to_nvs();
                                        removed = true;
                                    }
                                }

                                // Remove from whitelist if requested
                                if (strcmp(list_type, "whitelist") == 0 || strcmp(list_type, "both") == 0)
                                {
                                    if (remove_from_whitelist(mac) == ESP_OK)
                                    {
                                        save_whitelist_to_nvs();
                                        removed = true;
                                    }
                                }

                                if (removed)
                                {
                                    char response_buffer[256];
                                    snprintf(response_buffer, sizeof(response_buffer),
                                             "HTTP/1.1 200 OK\r\n"
                                             "Content-Type: application/json\r\n"
                                             "Connection: close\r\n\r\n"
                                             "{\"success\":true,\"message\":\"MAC removed from %s\"}",
                                             list_type);
                                    send(sock, response_buffer, strlen(response_buffer), 0);
                                    ESP_LOGI(TAG, "API: Removed MAC %s from %s", mac_str, list_type);
                                }
                                else
                                {
                                    const char *not_found_response =
                                        "HTTP/1.1 404 Not Found\r\n"
                                        "Content-Type: application/json\r\n"
                                        "Connection: close\r\n\r\n"
                                        "{\"success\":false,\"error\":\"MAC not found in specified list(s)\"}";
                                    send(sock, not_found_response, strlen(not_found_response), 0);
                                }
                            }
                            else
                            {
                                const char *error_response =
                                    "HTTP/1.1 400 Bad Request\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Connection: close\r\n\r\n"
                                    "{\"success\":false,\"error\":\"Invalid MAC address format (use XX:XX:XX:XX:XX:XX)\"}";
                                send(sock, error_response, strlen(error_response), 0);
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
                            "{\"success\":false,\"error\":\"Missing required parameters (api_key, mac)\"}";
                        send(sock, error_response, strlen(error_response), 0);
                    }
                }
                close(sock);
                continue;
            }

            // Handle POST /api/mac/clear - Clear blacklist/whitelist
            if (is_api_mac_clear)
            {
                REJECT_LOCAL_AP_REQUEST(sock, source_addr);

                char *body = strstr(rx_buffer, "\r\n\r\n");
                if (body != NULL)
                {
                    body += 4;
                    char received_key[API_KEY_LENGTH + 1] = {0};
                    char list_type[16] = "both"; // Default: clear both lists

                    // Parse parameters
                    char *key_start = strstr(body, "api_key=");
                    char *list_start = strstr(body, "list=");

                    if (key_start)
                    {
                        key_start += 8;
                        sscanf(key_start, "%32[^&\r\n]", received_key);

                        if (list_start)
                        {
                            list_start += 5;
                            sscanf(list_start, "%15[^&\r\n]", list_type);
                        }

                        if (strcmp(received_key, api_key) == 0)
                        {
                            int cleared = 0;

                            // Clear blacklist if requested
                            if (strcmp(list_type, "blacklist") == 0 || strcmp(list_type, "both") == 0)
                            {
                                cleared += blacklist_blob.entry_count;
                                memset(&blacklist_blob, 0, sizeof(blacklist_blob_t));
                                save_blacklist_to_nvs();
                            }

                            // Clear whitelist if requested
                            if (strcmp(list_type, "whitelist") == 0 || strcmp(list_type, "both") == 0)
                            {
                                cleared += whitelist_blob.entry_count;
                                memset(&whitelist_blob, 0, sizeof(whitelist_blob_t));
                                save_whitelist_to_nvs();
                            }

                            char response_buffer[256];
                            snprintf(response_buffer, sizeof(response_buffer),
                                     "HTTP/1.1 200 OK\r\n"
                                     "Content-Type: application/json\r\n"
                                     "Connection: close\r\n\r\n"
                                     "{\"success\":true,\"message\":\"Cleared %s\",\"entries_removed\":%d}",
                                     list_type, cleared);
                            send(sock, response_buffer, strlen(response_buffer), 0);
                            ESP_LOGI(TAG, "API: Cleared %s (%d entries)", list_type, cleared);
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
                                    is_api_token_extend || is_api_tokens_list || is_api_uptime || is_api_health ||
                                    is_api_mac_blacklist || is_api_mac_whitelist || is_api_mac_remove ||
                                    is_api_mac_list || is_api_mac_clear;

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

            // Handle admin token reset
            if (is_admin_reset_tokens)
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

                // Reset all tokens
                int tokens_removed = token_blob.token_count;
                memset(&token_blob, 0, sizeof(token_blob_t));
                save_tokens_blob_to_nvs();

                update_admin_activity();
                char response[256];
                snprintf(response, sizeof(response),
                         "HTTP/1.1 200 OK\r\n"
                         "Content-Type: application/json\r\n"
                         "Connection: close\r\n\r\n"
                         "{\"success\":true,\"message\":\"All tokens reset\",\"tokens_removed\":%d}",
                         tokens_removed);
                send(sock, response, strlen(response), 0);
                ESP_LOGI(TAG, "Admin: Reset all tokens (%d removed)", tokens_removed);
                close(sock);
                continue;
            }

            // Handle OTA firmware update
            if (is_admin_ota)
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

                if (ota_in_progress)
                {
                    const char *error =
                        "HTTP/1.1 409 Conflict\r\n"
                        "Content-Type: application/json\r\n"
                        "Connection: close\r\n\r\n"
                        "{\"success\":false,\"error\":\"OTA update already in progress\"}";
                    send(sock, error, strlen(error), 0);
                    close(sock);
                    continue;
                }

                // Parse multipart form data to extract firmware file
                char *body = strstr(rx_buffer, "\r\n\r\n");
                if (body == NULL)
                {
                    const char *error =
                        "HTTP/1.1 400 Bad Request\r\n"
                        "Content-Type: application/json\r\n"
                        "Connection: close\r\n\r\n"
                        "{\"success\":false,\"error\":\"Invalid request format\"}";
                    send(sock, error, strlen(error), 0);
                    close(sock);
                    continue;
                }
                body += 4; // Skip \r\n\r\n

                // Look for firmware file in multipart data
                char *firmware_start = strstr(body, "\r\n\r\n"); // End of headers, start of file data
                if (firmware_start == NULL)
                {
                    const char *error =
                        "HTTP/1.1 400 Bad Request\r\n"
                        "Content-Type: application/json\r\n"
                        "Connection: close\r\n\r\n"
                        "{\"success\":false,\"error\":\"No firmware file found\"}";
                    send(sock, error, strlen(error), 0);
                    close(sock);
                    continue;
                }
                firmware_start += 4; // Skip \r\n\r\n

                // Find end of firmware data (look for boundary)
                char *boundary = strstr(rx_buffer, "boundary=");
                if (boundary == NULL)
                {
                    const char *error =
                        "HTTP/1.1 400 Bad Request\r\n"
                        "Content-Type: application/json\r\n"
                        "Connection: close\r\n\r\n"
                        "{\"success\":false,\"error\":\"No boundary found\"}";
                    send(sock, error, strlen(error), 0);
                    close(sock);
                    continue;
                }
                boundary += 9; // Skip "boundary="
                char boundary_marker[128] = {0};
                int boundary_len = 0;
                while (boundary[boundary_len] && boundary[boundary_len] != '\r' && boundary[boundary_len] != '\n' && boundary_len < 127)
                {
                    boundary_marker[boundary_len] = boundary[boundary_len];
                    boundary_len++;
                }
                char full_boundary[140];
                snprintf(full_boundary, sizeof(full_boundary), "\r\n--%s", boundary_marker);

                char *firmware_end = strstr(firmware_start, full_boundary);
                if (firmware_end == NULL)
                {
                    const char *error =
                        "HTTP/1.1 400 Bad Request\r\n"
                        "Content-Type: application/json\r\n"
                        "Connection: close\r\n\r\n"
                        "{\"success\":false,\"error\":\"Could not determine firmware size\"}";
                    send(sock, error, strlen(error), 0);
                    close(sock);
                    continue;
                }

                size_t firmware_size = firmware_end - firmware_start;
                if (firmware_size == 0 || firmware_size > 1024 * 1024) // Max 1MB
                {
                    const char *error =
                        "HTTP/1.1 400 Bad Request\r\n"
                        "Content-Type: application/json\r\n"
                        "Connection: close\r\n\r\n"
                        "{\"success\":false,\"error\":\"Invalid firmware size\"}";
                    send(sock, error, strlen(error), 0);
                    close(sock);
                    continue;
                }

                // Validate firmware before proceeding with OTA
                if (!validate_firmware_for_ota((const uint8_t *)firmware_start, firmware_size))
                {
                    const char *error =
                        "HTTP/1.1 400 Bad Request\r\n"
                        "Content-Type: application/json\r\n"
                        "Connection: close\r\n\r\n"
                        "{\"success\":false,\"error\":\"Firmware validation failed. Invalid or incompatible binary.\"}";
                    send(sock, error, strlen(error), 0);
                    close(sock);
                    continue;
                }

                // Start OTA update
                ota_in_progress = true;
                esp_err_t err;

                // Get next OTA partition
                ota_partition = esp_ota_get_next_update_partition(NULL);
                if (ota_partition == NULL)
                {
                    ota_in_progress = false;
                    const char *error =
                        "HTTP/1.1 500 Internal Server Error\r\n"
                        "Content-Type: application/json\r\n"
                        "Connection: close\r\n\r\n"
                        "{\"success\":false,\"error\":\"No OTA partition available\"}";
                    send(sock, error, strlen(error), 0);
                    close(sock);
                    continue;
                }

                // Begin OTA
                err = esp_ota_begin(ota_partition, firmware_size, &ota_handle);
                if (err != ESP_OK)
                {
                    ota_in_progress = false;
                    char error_msg[256];
                    snprintf(error_msg, sizeof(error_msg),
                             "HTTP/1.1 500 Internal Server Error\r\n"
                             "Content-Type: application/json\r\n"
                             "Connection: close\r\n\r\n"
                             "{\"success\":false,\"error\":\"Failed to begin OTA: %s\"}",
                             esp_err_to_name(err));
                    send(sock, error_msg, strlen(error_msg), 0);
                    close(sock);
                    continue;
                }

                // Write firmware data
                err = esp_ota_write(ota_handle, firmware_start, firmware_size);
                if (err != ESP_OK)
                {
                    esp_ota_abort(ota_handle);
                    ota_in_progress = false;
                    char error_msg[256];
                    snprintf(error_msg, sizeof(error_msg),
                             "HTTP/1.1 500 Internal Server Error\r\n"
                             "Content-Type: application/json\r\n"
                             "Connection: close\r\n\r\n"
                             "{\"success\":false,\"error\":\"Failed to write firmware: %s\"}",
                             esp_err_to_name(err));
                    send(sock, error_msg, strlen(error_msg), 0);
                    close(sock);
                    continue;
                }

                // End OTA
                err = esp_ota_end(ota_handle);
                if (err != ESP_OK)
                {
                    ota_in_progress = false;
                    char error_msg[256];
                    snprintf(error_msg, sizeof(error_msg),
                             "HTTP/1.1 500 Internal Server Error\r\n"
                             "Content-Type: application/json\r\n"
                             "Connection: close\r\n\r\n"
                             "{\"success\":false,\"error\":\"Failed to end OTA: %s\"}",
                             esp_err_to_name(err));
                    send(sock, error_msg, strlen(error_msg), 0);
                    close(sock);
                    continue;
                }

                // Set boot partition
                err = esp_ota_set_boot_partition(ota_partition);
                if (err != ESP_OK)
                {
                    ota_in_progress = false;
                    char error_msg[256];
                    snprintf(error_msg, sizeof(error_msg),
                             "HTTP/1.1 500 Internal Server Error\r\n"
                             "Content-Type: application/json\r\n"
                             "Connection: close\r\n\r\n"
                             "{\"success\":false,\"error\":\"Failed to set boot partition: %s\"}",
                             esp_err_to_name(err));
                    send(sock, error_msg, strlen(error_msg), 0);
                    close(sock);
                    continue;
                }

                ota_in_progress = false;
                update_admin_activity();

                char response[512];
                snprintf(response, sizeof(response),
                         "HTTP/1.1 200 OK\r\n"
                         "Content-Type: application/json\r\n"
                         "Connection: close\r\n\r\n"
                         "{\"success\":true,\"message\":\"Firmware updated successfully. Rebooting in 5 seconds...\",\"partition\":\"%s\",\"size\":%d}",
                         ota_partition->label, firmware_size);
                send(sock, response, strlen(response), 0);

                ESP_LOGI(TAG, "Admin: OTA update completed, rebooting in 5 seconds");

                // Reboot after 5 seconds
                vTaskDelay(pdMS_TO_TICKS(5000));
                esp_restart();

                close(sock);
                continue;
            }

            // Handle AP SSID configuration
            if (is_admin_set_ap_ssid)
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
                    char new_ssid[33] = {0};
                    char admin_pass[64] = {0};

                    // Parse admin_password=XXX&ssid=XXX from POST body
                    char *admin_pass_start = strstr(body, "admin_password=");
                    char *ssid_start = strstr(body, "ssid=");

                    if (admin_pass_start && ssid_start)
                    {
                        // Parse admin password
                        admin_pass_start += 15; // skip "admin_password="
                        int i = 0;
                        int j = 0;
                        while (admin_pass_start[i] && admin_pass_start[i] != '&' &&
                               admin_pass_start[i] != '\r' && admin_pass_start[i] != '\n' && j < 63)
                        {
                            if (admin_pass_start[i] == '%' && admin_pass_start[i + 1] && admin_pass_start[i + 2])
                            {
                                char hex[3] = {admin_pass_start[i + 1], admin_pass_start[i + 2], 0};
                                admin_pass[j++] = (char)strtol(hex, NULL, 16);
                                i += 3; // Skip %XX
                            }
                            else if (admin_pass_start[i] == '+')
                            {
                                admin_pass[j++] = ' ';
                                i++;
                            }
                            else
                            {
                                admin_pass[j++] = admin_pass_start[i++];
                            }
                        }
                        admin_pass[j] = '\0';
                        ESP_LOGW(TAG, "Admin: Parsed password (length=%d)", j);

                        // Verify admin password
                        if (strcmp(admin_pass, admin_password) != 0)
                        {
                            const char *error =
                                "HTTP/1.1 401 Unauthorized\r\n"
                                "Content-Type: application/json\r\n"
                                "Connection: close\r\n\r\n"
                                "{\"success\":false,\"error\":\"Incorrect admin password\"}";
                            send(sock, error, strlen(error), 0);
                            ESP_LOGW(TAG, "Admin: Failed AP SSID change attempt - incorrect password");
                            close(sock);
                            continue;
                        }

                        // Parse SSID
                        ssid_start = strstr(body, "ssid=");
                        if (ssid_start)
                        {
                            ssid_start += 5; // skip "ssid="
                            i = 0;
                            j = 0;
                            while (ssid_start[i] && ssid_start[i] != '&' &&
                                   ssid_start[i] != '\r' && ssid_start[i] != '\n' && j < 32)
                            {
                                // URL decode if needed (basic %20 -> space, %2B -> +, etc.)
                                if (ssid_start[i] == '%' && ssid_start[i + 1] && ssid_start[i + 2])
                                {
                                    char hex[3] = {ssid_start[i + 1], ssid_start[i + 2], 0};
                                    new_ssid[j++] = (char)strtol(hex, NULL, 16);
                                    i += 3; // Skip %XX
                                }
                                else if (ssid_start[i] == '+')
                                {
                                    new_ssid[j++] = ' '; // + is space in URL encoding
                                    i++;
                                }
                                else
                                {
                                    new_ssid[j++] = ssid_start[i++];
                                }
                            }
                            new_ssid[j] = '\0';
                            ESP_LOGW(TAG, "Admin: Parsed new SSID: \"%s\" (length=%d)", new_ssid, j);

                            // Validate SSID
                            if (!is_valid_ssid(new_ssid))
                            {
                                const char *error =
                                    "HTTP/1.1 400 Bad Request\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Connection: close\r\n\r\n"
                                    "{\"success\":false,\"error\":\"Invalid SSID (must be 1-32 printable ASCII characters)\"}";
                                send(sock, error, strlen(error), 0);
                                ESP_LOGW(TAG, "Admin: Invalid SSID rejected: \"%s\"", new_ssid);
                                close(sock);
                                continue;
                            }

                            // Save new SSID to NVS
                            ESP_LOGW(TAG, "Admin: Attempting to save new AP SSID: \"%s\"", new_ssid);
                            esp_err_t err = save_ap_ssid(new_ssid);
                            ESP_LOGW(TAG, "Admin: save_ap_ssid returned: %s", esp_err_to_name(err));

                            if (err == ESP_OK)
                            {
                                update_admin_activity();
                                const char *response =
                                    "HTTP/1.1 200 OK\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Connection: close\r\n\r\n"
                                    "{\"success\":true,\"message\":\"AP SSID will be updated after reboot\",\"reboot\":true}";
                                send(sock, response, strlen(response), 0);
                                ESP_LOGW(TAG, "▶▶▶ Admin: Response sent - AP SSID will change to \"%s\" after reboot", new_ssid);

                                // Close socket and delay before reboot
                                close(sock);
                                ESP_LOGW(TAG, "▶▶▶ Socket closed, waiting 1 second before reboot...");
                                vTaskDelay(pdMS_TO_TICKS(1000)); // Give time for response to send

                                ESP_LOGE(TAG, "⚠️⚠️⚠️  REBOOTING ESP32 NOW TO APPLY NEW AP SSID...");
                                fflush(stdout); // Ensure log is written
                                esp_restart();  // THIS SHOULD REBOOT THE DEVICE

                                // Should never reach here
                                ESP_LOGE(TAG, "❌ ERROR: esp_restart() did not reboot! This should never happen!");
                            }
                            else
                            {
                                const char *error =
                                    "HTTP/1.1 500 Internal Server Error\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Connection: close\r\n\r\n"
                                    "{\"success\":false,\"error\":\"Failed to save AP SSID\"}";
                                send(sock, error, strlen(error), 0);
                                ESP_LOGE(TAG, "Admin: Failed to save AP SSID: %s", esp_err_to_name(err));
                            }
                        }
                    }
                    else
                    {
                        const char *error =
                            "HTTP/1.1 400 Bad Request\r\n"
                            "Content-Type: application/json\r\n"
                            "Connection: close\r\n\r\n"
                            "{\"success\":false,\"error\":\"Missing admin_password or ssid parameter\"}";
                        send(sock, error, strlen(error), 0);
                        ESP_LOGW(TAG, "Admin: Missing parameters for AP SSID change");
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

                    // AP Settings card
                    char ap_ssid_card[896];
                    snprintf(ap_ssid_card, sizeof(ap_ssid_card),
                             "<div class='card'><h2>📡 Access Point Settings</h2>"
                             "<p style='color:#666;margin-bottom:15px'>Customize your captive portal SSID</p>"
                             "<form id='apSsidForm'>"
                             "<label>Admin Password:</label>"
                             "<input type='password' id='apSsidAdminPass' required>"
                             "<label>AP SSID Name:</label>"
                             "<input type='text' id='apSsid' value='%s' maxlength='32' required "
                             "pattern='[\\x20-\\x7E]{1,32}' title='1-32 printable ASCII characters'>"
                             "<p style='font-size:12px;color:#666;margin:5px 0'>1-32 characters (letters, numbers, spaces, symbols)</p>"
                             "<button type='submit' class='danger'>Update AP SSID</button>"
                             "<div class='info-box' style='margin-top:15px'>"
                             "<strong>⚠️ Warning:</strong> Changing the SSID will <strong>reboot the ESP32</strong>. "
                             "All guests and admin connections will be dropped.</div>"
                             "</form></div>",
                             ap_ssid);
                    send(sock, ap_ssid_card, strlen(ap_ssid_card), 0);

                    // Password change card
                    const char *pass_card =
                        "<div class='card'><h2>🔐 Change Password</h2>"
                        "<form id='passForm'>"
                        "<label>Current Password:</label><input type='password' id='oldPass' required>"
                        "<label>New Password:</label><input type='password' id='newPass' required>"
                        "<label>Confirm New Password:</label><input type='password' id='confirmPass' required>"
                        "<button type='submit' class='danger'>Change Password</button></form></div>";

                    // OTA Firmware Update card
                    const char *ota_card =
                        "<div class='card'><h2>🚀 Firmware Update</h2>"
                        "<p style='color:#666;margin-bottom:15px'>Upload new firmware for over-the-air update</p>"
                        "<form id='otaForm' enctype='multipart/form-data'>"
                        "<label>Firmware File (.bin):</label>"
                        "<input type='file' id='firmwareFile' accept='.bin' required style='margin-bottom:10px'>"
                        "<div id='otaProgress' style='display:none;margin:10px 0'>"
                        "<div style='width:100%;background:#e9ecef;border-radius:4px;height:20px'>"
                        "<div id='progressBar' style='width:0%;height:100%;background:#007bff;border-radius:4px;transition:width 0.3s'></div>"
                        "</div><div id='progressText' style='text-align:center;margin-top:5px'>Preparing...</div></div>"
                        "<button type='submit' id='otaBtn'>Update Firmware</button></form>"
                        "<div class='info-box' style='margin-top:15px'>"
                        "<strong>⚠️ Warning:</strong> Firmware update will reboot the ESP32. Ensure you have a backup and stable connection.</div></div>"
                        "</div></div>";
                    send(sock, pass_card, strlen(pass_card), 0);
                    send(sock, ota_card, strlen(ota_card), 0);

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
                        "fetch('/admin/configure',{method:'POST',body:data}).then(r=>r.text()).then(()=>{alert('WiFi updated! Reconnecting...');setTimeout(updateStatus,5000)})});"
                        "document.getElementById('apSsidForm').addEventListener('submit',function(e){"
                        "e.preventDefault();var adminPass=document.getElementById('apSsidAdminPass').value;"
                        "var newSsid=document.getElementById('apSsid').value;"
                        "if(!adminPass){alert('Admin password is required');return}"
                        "if(newSsid.length<1||newSsid.length>32){alert('SSID must be 1-32 characters');return}"
                        "if(!confirm('⚠️ REBOOT WARNING ⚠️\\n\\nChanging AP SSID to \"'+newSsid+'\" will:\\n• Reboot the ESP32\\n• Disconnect all users (including you)\\n• Take 30-60 seconds\\n\\nContinue?')){return}"
                        "var data='admin_password='+encodeURIComponent(adminPass)+'&ssid='+encodeURIComponent(newSsid);"
                        "fetch('/admin/set_ap_ssid',{method:'POST',body:data}).then(r=>r.json()).then(d=>{"
                        "if(d.success){alert('AP SSID saved! ESP32 is rebooting now...\\n\\nWait 30-60 seconds, then reconnect to: '+newSsid);document.getElementById('apSsidAdminPass').value=''}"
                        "else{alert('Error: '+d.error);document.getElementById('apSsidAdminPass').value=''}}).catch(()=>{alert('ESP32 is rebooting. Wait 30-60 seconds then reconnect to: '+newSsid)})});";
                    send(sock, script1, strlen(script1), 0);

                    // JavaScript part 2
                    const char *script2 =
                        "document.getElementById('otaForm').addEventListener('submit',function(e){"
                        "e.preventDefault();var file=document.getElementById('firmwareFile').files[0];"
                        "if(!file){alert('Please select a firmware file');return}"
                        "if(!file.name.endsWith('.bin')){alert('Please select a .bin file');return}"
                        "if(file.size>1024*1024){alert('File too large (max 1MB)');return}"
                        "if(!confirm('⚠️ FIRMWARE UPDATE WARNING ⚠️\\n\\nThis will:\\n• Upload and flash new firmware\\n• Reboot the ESP32\\n• Disconnect all users\\n\\nContinue?')){return}"
                        "document.getElementById('otaProgress').style.display='block';"
                        "document.getElementById('progressText').textContent='Reading file...';"
                        "document.getElementById('otaBtn').disabled=true;"
                        "var reader=new FileReader();reader.onload=function(){"
                        "document.getElementById('progressText').textContent='Uploading firmware...';"
                        "document.getElementById('progressBar').style.width='50%';"
                        "var formData=new FormData();formData.append('firmware',file);"
                        "fetch('/admin/ota',{method:'POST',body:formData}).then(r=>r.json()).then(d=>{"
                        "if(d.success){document.getElementById('progressBar').style.width='100%';"
                        "document.getElementById('progressText').textContent='Update successful! Rebooting...';"
                        "setTimeout(()=>{alert('Firmware updated! ESP32 is rebooting. Wait 30-60 seconds then reconnect.');window.location.reload()},3000)}"
                        "else{alert('OTA failed: '+d.error);document.getElementById('otaProgress').style.display='none';document.getElementById('otaBtn').disabled=false}}).catch(()=>{"
                        "alert('OTA failed: Network error');document.getElementById('otaProgress').style.display='none';document.getElementById('otaBtn').disabled=false})};reader.readAsArrayBuffer(file)});"
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
                                  is_admin_login || is_admin_logout || is_admin_change_pass || is_admin_regen_key ||
                                  is_admin_generate_token || is_admin_reset_tokens || is_admin_set_ap_ssid ||
                                  is_admin_ota ||
                                  is_customer_status || is_api_token || is_api_token_disable ||
                                  is_api_token_info || is_api_token_batch_info || is_api_token_extend ||
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

                    // Check if MAC is blacklisted before showing login page
                    uint8_t client_mac[6] = {0};
                    memcpy(client_mac, &source_addr.sin_addr.s_addr, 4);

                    if (is_mac_blacklisted(client_mac))
                    {
                        // Find blacklist entry to get reason
                        const char *reason = "Access blocked by administrator";
                        for (int i = 0; i < blacklist_blob.entry_count && i < MAX_BLACKLIST_ENTRIES; i++)
                        {
                            if (blacklist_blob.entries[i].active && memcmp(blacklist_blob.entries[i].mac, client_mac, 6) == 0)
                            {
                                if (strlen(blacklist_blob.entries[i].reason) > 0)
                                {
                                    reason = blacklist_blob.entries[i].reason;
                                }
                                break;
                            }
                        }

                        // Format MAC address for display
                        char mac_display[18];
                        snprintf(mac_display, sizeof(mac_display), "%02X:%02X:%02X:%02X:%02X:%02X",
                                 client_mac[0], client_mac[1], client_mac[2],
                                 client_mac[3], client_mac[4], client_mac[5]);

                        // Show blacklist blocked page
                        char blocked_response[2048];
                        snprintf(blocked_response, sizeof(blocked_response),
                                 "HTTP/1.1 403 Forbidden\r\n"
                                 "Content-Type: text/html; charset=UTF-8\r\n"
                                 "Connection: close\r\n"
                                 "\r\n"
                                 "<!DOCTYPE html>"
                                 "<html><head><meta charset='UTF-8'><title>Access Denied</title>"
                                 "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                                 "<style>body{font-family:Arial;margin:40px;text-align:center;background:#f0f0f0}"
                                 ".box{background:white;padding:30px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1);max-width:400px;margin:0 auto}"
                                 "h1{color:#dc3545}.icon{font-size:48px;margin-bottom:20px}"
                                 "p{color:#666;margin:10px 0}.mac{font-family:monospace;background:#f8f9fa;padding:8px;border-radius:4px;color:#333}"
                                 ".reason{font-weight:bold;color:#dc3545;margin-top:20px}"
                                 ".info{margin-top:30px;font-size:12px;color:#999}</style>"
                                 "</head><body><div class='box'>"
                                 "<div class='icon'>🚫</div>"
                                 "<h1>Access Denied</h1>"
                                 "<p>Your device has been blocked from accessing this network.</p>"
                                 "<p class='mac'>MAC: %s</p>"
                                 "<p class='reason'>Reason: %s</p>"
                                 "<p class='info'>If you believe this is an error, please contact the network administrator.</p>"
                                 "</div></body></html>",
                                 mac_display, reason);

                        send(sock, blocked_response, strlen(blocked_response), 0);
                        ESP_LOGW(TAG, "Blocked blacklisted MAC %s from accessing portal", mac_display);
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

    // Initialize NVS with comprehensive recovery for fragmented storage
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    // Additional recovery for severely fragmented NVS (from old per-token storage)
    if (ret == ESP_ERR_NVS_NOT_ENOUGH_SPACE)
    {
        ESP_LOGW(TAG, "NVS severely fragmented, performing full recovery...");
        // Try to deinit if already initialized, but don't fail if not
        nvs_flash_deinit();
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
        ESP_LOGI(TAG, "NVS fully recovered and reinitialized");
    }
    ESP_ERROR_CHECK(ret);

    // Initialize dedicated NVS partition for tokens
    ret = nvs_flash_init_partition("nvs_tokens");
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase_partition("nvs_tokens"));
        ret = nvs_flash_init_partition("nvs_tokens");
    }
    ESP_ERROR_CHECK(ret);
    ESP_LOGI(TAG, "✓ Token NVS partition initialized");

    // Initialize heartbeat LED (fast blink mode)
    heartbeat_init(HEARTBEAT_LED_GPIO);
    ESP_LOGI(TAG, "✓ Heartbeat LED initialized (fast blink - waiting for WiFi)");

    // Time will be synced via SNTP after WiFi connection
    ESP_LOGI(TAG, "Time sync will occur after WiFi connection");

    // Load admin password and API key
    load_admin_password();
    load_or_generate_api_key();

    // Load existing tokens from NVS
    load_tokens_blob_from_nvs();

    // Initialize MAC filtering blobs and load from NVS
    memset(&blacklist_blob, 0, sizeof(blacklist_blob_t));
    memset(&whitelist_blob, 0, sizeof(whitelist_blob_t));
    load_blacklist_from_nvs();
    load_whitelist_from_nvs();

    // Load WiFi credentials from NVS (or use defaults)
    load_wifi_credentials();

    // Load AP SSID from NVS (or use default)
    load_ap_ssid();

    // Tokens will be created via admin panel after time sync
    ESP_LOGI(TAG, "Loaded %d tokens from storage", token_blob.token_count);

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
            .ssid_len = 0, // Will be set below
            .channel = MESH_CHANNEL,
            .password = "",
            .max_connection = 4,
            .authmode = WIFI_AUTH_OPEN,
        },
    };
    // Copy AP SSID from loaded/default value
    strncpy((char *)wifi_config_ap.ap.ssid, ap_ssid, sizeof(wifi_config_ap.ap.ssid));
    wifi_config_ap.ap.ssid_len = strlen(ap_ssid);
    ESP_LOGI(TAG, "Configuring AP with SSID: \"%s\"", ap_ssid);
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
            .ssid_len = 0, // Will be set below
            .channel = MESH_CHANNEL,
            .password = "",
            .max_connection = 4,
            .authmode = WIFI_AUTH_OPEN,
            .pmf_cfg = {
                .required = false,
            },
        },
    };
    // Copy AP SSID from loaded/default value
    strncpy((char *)ap_config.ap.ssid, ap_ssid, sizeof(ap_config.ap.ssid));
    ap_config.ap.ssid_len = strlen(ap_ssid);
    ESP_LOGI(TAG, "Configuring AP with SSID: \"%s\"", ap_ssid);
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

    ESP_LOGI(TAG, "✓ TOKEN SYSTEM ACTIVE: %d tokens loaded", token_blob.token_count);
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
                 token_blob.token_count,
                 authenticated_count);
#endif
    }
}
