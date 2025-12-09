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

static const char *TAG = "esp32-mesh-portal";

// Mesh configuration
#define MESH_ID "ESP32-PORTAL-MESH"
#define MESH_PASSWORD "meshpass123"
#define MESH_CHANNEL 4 // Same as uplink WiFi channel
#define MESH_MAX_LAYER 6
#define MESH_ROUTER_SSID "TP-Link_521B"
#define MESH_ROUTER_PASS "08042024"

// Admin configuration
#define ADMIN_PASSWORD "admin123"
#define WIFI_SSID_KEY "wifi_ssid"
#define WIFI_PASS_KEY "wifi_pass"

// Current WiFi credentials (loaded from NVS or defaults)
static char current_wifi_ssid[32] = MESH_ROUTER_SSID;
static char current_wifi_pass[64] = MESH_ROUTER_PASS;

// Mesh state
static bool mesh_connected = false;
static int mesh_layer = -1;

// Network interfaces
static esp_netif_t *sta_netif = NULL;
static esp_netif_t *ap_netif = NULL;

// Token management
#define TOKEN_LENGTH 8
#define TOKEN_EXPIRY_HOURS 24
#define MAX_TOKENS 50

typedef struct
{
    char token[TOKEN_LENGTH + 1];
    time_t created;
    time_t expires;
    uint32_t usage_count;
    uint8_t client_mac[6];
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
            if (now > active_tokens[token_count].expires)
            {
                ESP_LOGI(TAG, "Token %s expired, removing", active_tokens[token_count].token);
                active_tokens[token_count].active = false;
            }
            else
            {
                ESP_LOGI(TAG, "Loaded token %s (used %lu times)",
                         active_tokens[token_count].token,
                         active_tokens[token_count].usage_count);
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

// Create new access token
static esp_err_t create_new_token(char *token_out)
{
    if (token_count >= MAX_TOKENS)
    {
        ESP_LOGE(TAG, "Maximum token limit reached");
        return ESP_ERR_NO_MEM;
    }

    token_info_t new_token;
    generate_token(new_token.token);

    time_t now = time(NULL);
    new_token.created = now;
    new_token.expires = now + (TOKEN_EXPIRY_HOURS * 3600);
    new_token.usage_count = 0;
    memset(new_token.client_mac, 0, 6);
    new_token.active = true;

    // Save to NVS
    esp_err_t err = save_token_to_nvs(new_token.token, &new_token);
    if (err != ESP_OK)
    {
        return err;
    }

    // Add to active tokens
    memcpy(&active_tokens[token_count], &new_token, sizeof(token_info_t));
    token_count++;

    strcpy(token_out, new_token.token);
    ESP_LOGI(TAG, "✓ Created new token: %s (expires in %d hours)", token_out, TOKEN_EXPIRY_HOURS);

    return ESP_OK;
}

// Validate token and bind to client MAC
static bool validate_token(const char *token, const uint8_t *client_mac)
{
    time_t now = time(NULL);

    for (int i = 0; i < token_count; i++)
    {
        if (!active_tokens[i].active)
            continue;

        if (strcmp(active_tokens[i].token, token) == 0)
        {
            // Check expiration
            if (now > active_tokens[i].expires)
            {
                ESP_LOGW(TAG, "Token %s has expired", token);
                active_tokens[i].active = false;
                return false;
            }

            // Check if token is already bound to a different MAC
            bool is_bound = false;
            for (int j = 0; j < 6; j++)
            {
                if (active_tokens[i].client_mac[j] != 0)
                {
                    is_bound = true;
                    break;
                }
            }

            if (is_bound)
            {
                // Verify MAC matches
                if (memcmp(active_tokens[i].client_mac, client_mac, 6) != 0)
                {
                    ESP_LOGW(TAG, "Token %s already bound to different device", token);
                    return false;
                }
            }
            else
            {
                // Bind token to this MAC
                memcpy(active_tokens[i].client_mac, client_mac, 6);
                ESP_LOGI(TAG, "Token %s bound to MAC: %02X:%02X:%02X:%02X:%02X:%02X",
                         token,
                         client_mac[0], client_mac[1], client_mac[2],
                         client_mac[3], client_mac[4], client_mac[5]);
                save_token_to_nvs(active_tokens[i].token, &active_tokens[i]);
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

// WiFi connection tracking
static int wifi_retry_num = 0;
#define MAX_WIFI_RETRY 5

// Reconnect WiFi with new credentials
static void reconnect_wifi(void)
{
    ESP_LOGI(TAG, "Reconnecting WiFi with new credentials...");
    
    // Reset retry counter
    wifi_retry_num = 0;
    
    // Disconnect current STA connection
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(1000));    // Update WiFi configuration
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

        // Check if client is authenticated - if so, forward DNS to real server
        uint32_t client_ip = source_addr.sin_addr.s_addr;
        if (is_client_authenticated(client_ip))
        {
            ESP_LOGI(TAG, "DNS: Forwarding query from authenticated client " IPSTR,
                     IP2STR((esp_ip4_addr_t *)&client_ip));

            // Forward DNS query to Google DNS (8.8.8.8)
            struct sockaddr_in dns_server;
            dns_server.sin_family = AF_INET;
            dns_server.sin_port = htons(53);
            inet_pton(AF_INET, "8.8.8.8", &dns_server.sin_addr);

            // Forward the query
            int forward_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (forward_sock >= 0)
            {
                // Set timeout for receiving response
                struct timeval timeout;
                timeout.tv_sec = 2;
                timeout.tv_usec = 0;
                setsockopt(forward_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

                // Send query to 8.8.8.8
                int sent = sendto(forward_sock, rx_buffer, len, 0,
                                  (struct sockaddr *)&dns_server, sizeof(dns_server));
                ESP_LOGI(TAG, "DNS: Sent %d bytes to 8.8.8.8", sent);

                // Receive response from 8.8.8.8
                char forward_response[512];
                int response_len = recvfrom(forward_sock, forward_response, sizeof(forward_response), 0, NULL, NULL);

                if (response_len > 0)
                {
                    ESP_LOGI(TAG, "DNS: Received %d bytes from 8.8.8.8, forwarding to client", response_len);
                    // Forward response back to client
                    sendto(sock, forward_response, response_len, 0,
                           (struct sockaddr *)&source_addr, sizeof(source_addr));
                }
                else
                {
                    ESP_LOGW(TAG, "DNS: No response from 8.8.8.8 (timeout or error)");
                }
                close(forward_sock);
            }
            else
            {
                ESP_LOGE(TAG, "DNS: Failed to create forward socket");
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
    // Bind only to AP IP (192.168.4.1) to avoid intercepting forwarded traffic
    dest_addr.sin_addr.s_addr = inet_addr("192.168.4.1");
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

                    // Parse admin_password=XXX&ssid=XXX&password=XXX
                    char *admin_pass_start = strstr(body, "admin_password=");
                    char *ssid_start = strstr(body, "&ssid=");
                    char *pass_start = NULL;
                    
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

                        // Debug logging
                        ESP_LOGI(TAG, "Admin config received - SSID: '%s', Password length: %d", new_ssid, strlen(new_pass));
                        ESP_LOGI(TAG, "Password bytes: %02X %02X %02X %02X %02X %02X %02X %02X", 
                                 new_pass[0], new_pass[1], new_pass[2], new_pass[3],
                                 new_pass[4], new_pass[5], new_pass[6], new_pass[7]);

                        // Verify admin password
                        if (strcmp(admin_pass, ADMIN_PASSWORD) == 0)
                        {
                            // Save and reconnect
                            esp_err_t err = save_wifi_credentials(new_ssid, new_pass);
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

                char status_json[512];
                snprintf(status_json, sizeof(status_json),
                         "HTTP/1.1 200 OK\r\n"
                         "Content-Type: application/json\r\n"
                         "Connection: close\r\n\r\n"
                         "{\"sta_connected\":%s,\"ssid\":\"%s\",\"rssi\":%d,\"current_ssid\":\"%s\"}",
                         sta_connected ? "true" : "false",
                         sta_connected ? (char *)ap_info.ssid : "Not connected",
                         sta_connected ? ap_info.rssi : 0,
                         current_wifi_ssid);
                send(sock, status_json, strlen(status_json), 0);
                close(sock);
                continue;
            }

            // Handle admin page
            if (is_admin_page)
            {
                const char *admin_page =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    "Connection: close\r\n\r\n"
                    "<!DOCTYPE html><html><head><title>Admin Panel</title>"
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                    "<style>body{font-family:Arial;margin:20px;background:#f0f0f0}"
                    ".container{max-width:600px;margin:0 auto;background:white;padding:30px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1)}"
                    "h1{color:#333;margin-top:0}.section{margin:20px 0;padding:20px;background:#f8f9fa;border-radius:5px}"
                    "label{display:block;margin:10px 0 5px;font-weight:bold;color:#555}"
                    "input{width:100%;padding:10px;border:1px solid #ddd;border-radius:5px;box-sizing:border-box;margin-bottom:15px}"
                    "button{background:#007bff;color:white;padding:12px 20px;border:none;border-radius:5px;cursor:pointer;width:100%}"
                    "button:hover{background:#0056b3}.status{padding:10px;background:#e7f3ff;border-left:4px solid #007bff;margin:10px 0}"
                    ".info{font-size:12px;color:#666;margin-top:10px}.warning{color:#dc3545;font-weight:bold}"
                    "</style></head><body><div class='container'>"
                    "<h1>🔧 Admin Panel</h1>"
                    "<div class='section'><h2>WiFi Uplink Configuration</h2>"
                    "<div id='status' class='status'>Loading status...</div>"
                    "<form method='POST' action='/admin/configure' onsubmit='return confirm(\"Update WiFi configuration?\")'>"
                    "<label>Admin Password:</label>"
                    "<input type='password' name='admin_password' placeholder='Enter admin password' required>"
                    "<label>Router SSID:</label>"
                    "<input type='text' name='ssid' placeholder='Enter WiFi network name' value='%s' required>"
                    "<label>Router Password:</label>"
                    "<input type='password' name='password' placeholder='Enter WiFi password' value='%s' required>"
                    "<button type='submit'>Update Configuration</button>"
                    "</form>"
                    "<div class='info'>Current SSID: <strong>%s</strong><br>"
                    "Default admin password: <span class='warning'>admin123</span> (change in code)</div>"
                    "</div></div>"
                    "<script>fetch('/admin/status').then(r=>r.json()).then(d=>{"
                    "document.getElementById('status').innerHTML="
                    "'Status: '+(d.sta_connected?'<strong style=\"color:green\">✓ Connected</strong>':'<strong style=\"color:red\">✗ Disconnected</strong>')+"
                    "' | SSID: '+d.ssid+' | RSSI: '+d.rssi+' dBm';"
                    "});</script></body></html>";

                char response[4096];
                snprintf(response, sizeof(response), admin_page,
                         current_wifi_ssid, "", current_wifi_ssid);
                send(sock, response, strlen(response), 0);
                close(sock);
                continue;
            }

            // If authenticated and NOT trying to login or admin, close connection to let traffic through
            if (is_authenticated && !is_post_login && !is_admin_page && !is_admin_config && !is_admin_status)
            {
                ESP_LOGI(TAG, "Authenticated client - closing connection to allow direct internet access");
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

                            // Success response
                            const char *success_response =
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: text/html\r\n"
                                "Connection: close\r\n"
                                "\r\n"
                                "<!DOCTYPE html>"
                                "<html><head><title>Connected</title>"
                                "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                                "<style>body{font-family:Arial;margin:40px;text-align:center;background:#f0f0f0}"
                                ".box{background:white;padding:30px;border-radius:10px;box-shadow:0 2px 10px rgba(0,0,0,0.1);max-width:400px;margin:0 auto}"
                                "h1{color:#28a745}.status{color:#666;margin-top:20px}button{background:#007bff;color:white;padding:12px;border:none;border-radius:5px;cursor:pointer;margin-top:15px}"
                                "</style></head><body><div class='box'>"
                                "<h1>✓ Connected!</h1>"
                                "<p>Your device is now connected to the internet.</p>"
                                "<div class='status'><strong>Token:</strong> %s<br><strong>Valid for:</strong> %d hours</div>"
                                "</div></body></html>";

                            char response[2048];
                            snprintf(response, sizeof(response), success_response, token, TOKEN_EXPIRY_HOURS);
                            send(sock, response, strlen(response), 0);
                        }
                        else
                        {
                            // Invalid token response
                            const char *error_response =
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: text/html\r\n"
                                "Connection: close\r\n"
                                "\r\n"
                                "<!DOCTYPE html>"
                                "<html><head><title>Invalid Token</title>"
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
                // Show login page
                const char *response =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "<!DOCTYPE html>"
                    "<html><head><title>ESP32 Portal</title>"
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
                    "<p class='info'>Token expires in 24 hours after first use<br>Phase 2: Token validation active</p>"
                    "<a href='/admin' class='admin-link'>🔧 Admin Panel</a>"
                    "</div></body></html>";

                send(sock, response, strlen(response), 0);
            }
        }

        close(sock);
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

    // Initialize time (needed for token expiration)
    struct timeval tv_now = {.tv_sec = 1733616000}; // Set to Dec 8, 2025
    settimeofday(&tv_now, NULL);
    setenv("TZ", "UTC", 1);
    tzset();

    // Load existing tokens from NVS
    load_tokens_from_nvs();

    // Load WiFi credentials from NVS (or use defaults)
    load_wifi_credentials();

    // Create some test tokens if none exist
    if (token_count == 0)
    {
        ESP_LOGI(TAG, "Creating initial test tokens...");
        char token[TOKEN_LENGTH + 1];
        for (int i = 0; i < 5; i++)
        {
            if (create_new_token(token) == ESP_OK)
            {
                ESP_LOGI(TAG, "Test token %d: %s", i + 1, token);
            }
        }
    }

    // Initialize TCP/IP and WiFi
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Create default WiFi station and AP with stored references
    sta_netif = esp_netif_create_default_wifi_sta();
    ap_netif = esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // Register WiFi event handlers (still needed for STA events)
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

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    // Configure AP
    wifi_config_t wifi_config_ap = {
        .ap = {
            .ssid = "ESP32-Guest-Portal",
            .ssid_len = strlen("ESP32-Guest-Portal"),
            .channel = 4,
            .password = "",
            .max_connection = 4,
            .authmode = WIFI_AUTH_OPEN,
        },
    };

    // Configure STA to connect to your home router (use loaded credentials)
    wifi_config_t wifi_config_sta = {0};
    strncpy((char *)wifi_config_sta.sta.ssid, current_wifi_ssid, sizeof(wifi_config_sta.sta.ssid));
    strncpy((char *)wifi_config_sta.sta.password, current_wifi_pass, sizeof(wifi_config_sta.sta.password));

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config_ap));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config_sta));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "✓ WiFi started - AP: ESP32-Guest-Portal, connecting to: %s", current_wifi_ssid);

    // Connect to router
    esp_wifi_connect();

    // Wait for STA connection
    ESP_LOGI(TAG, "Waiting for connection to router...");
    vTaskDelay(pdMS_TO_TICKS(5000));

    // Always proceed - start services (NAT will work when STA connects)
    if (true)
    {
        ESP_LOGI(TAG, "✓ Starting captive portal services");

        // Enable NAT for internet routing from mesh to internet
        esp_netif_ip_info_t ap_ip_info;
        esp_netif_get_ip_info(ap_netif, &ap_ip_info);

        esp_netif_ip_info_t sta_ip_info;
        esp_netif_get_ip_info(sta_netif, &sta_ip_info);

        // Enable NAPT on the AP interface for mesh and guest clients
        ip_napt_enable(ap_ip_info.ip.addr, 1);
        ESP_LOGI(TAG, "✓ NAT ENABLED on AP: " IPSTR " forwarding through STA: " IPSTR,
                 IP2STR(&ap_ip_info.ip), IP2STR(&sta_ip_info.ip));

        ESP_LOGI(TAG, "✓ MESH NETWORK ACTIVE: %s", MESH_ID);
        ESP_LOGI(TAG, "✓ TOKEN SYSTEM ACTIVE: %d tokens loaded", token_count);
        ESP_LOGI(TAG, "Starting DNS and HTTP servers...");

        // Start DNS server for captive portal redirect
        xTaskCreate(dns_server_task, "dns_server", 4096, NULL, 5, NULL);

        // Start HTTP server for captive portal with token validation
        xTaskCreate(http_server_task, "http_server", 8192, NULL, 5, NULL);

        ESP_LOGI(TAG, "✓ CAPTIVE PORTAL ACTIVE (with token validation)");
    }

    // Keep running
    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(10000));
        ESP_LOGI(TAG, "System: Tokens=%d, Authenticated=%d",
                 token_count,
                 authenticated_count);
    }
}
