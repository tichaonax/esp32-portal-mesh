#include "heartbeat.h"
#include "esp_log.h"
#include "esp_timer.h"

#define TAG "HEARTBEAT"

// Timing in microseconds
#define FAST_INTERVAL_US         125000     // 125ms for fast heartbeat toggle
#define SLOW_HEARTBEAT_PERIOD_US 2000000    // 2 seconds for slow heartbeat cycle
#define SLOW_HEARTBEAT_ON_US     125000     // LED ON duration in slow mode (125ms)

#define TRAFFIC_ON_US            100000     // 100ms ON
#define TRAFFIC_OFF_US           100000     // 100ms OFF
#define TRAFFIC_BLINK_LIMIT      6          // 3 blinks (ON+OFF) = 6 steps

static gpio_num_t led_gpio_pin;

// LED control
static void set_led(bool on) {
    gpio_set_level(led_gpio_pin, on ? 1 : 0);
}

// Internal states
static bool wifi_connected = false;
static bool led_state = false;
static bool burst_active = false;
static int traffic_blink_count = 0;

// ESP Timers
static esp_timer_handle_t fast_timer;
static esp_timer_handle_t slow_timer_on;
static esp_timer_handle_t slow_timer_off;
static esp_timer_handle_t traffic_timer;

// ----------------------------
// TIMER CALLBACKS
// ----------------------------

// Fast toggle (WiFi disconnected)
static void fast_blink_cb(void *arg) {
    led_state = !led_state;
    set_led(led_state);
}

// Slow heartbeat ON (WiFi connected)
static void slow_heartbeat_on_cb(void *arg) {
    if (burst_active) return;  // Let traffic blink override LED

    set_led(true);
    esp_timer_start_once(slow_timer_off, SLOW_HEARTBEAT_ON_US);
}

// Slow heartbeat OFF
static void slow_heartbeat_off_cb(void *arg) {
    if (!burst_active) {
        set_led(false);
    }
}

// Traffic blink (3 short blinks)
static void traffic_burst_cb(void *arg) {
    traffic_blink_count++;

    if (traffic_blink_count % 2 == 1) {
        set_led(true);  // ON
    } else {
        set_led(false); // OFF
    }

    if (traffic_blink_count < TRAFFIC_BLINK_LIMIT) {
        esp_timer_start_once(traffic_timer, TRAFFIC_ON_US);
    } else {
        burst_active = false;
        traffic_blink_count = 0;

        // If we're in the "connected" state, make sure heartbeat resumes cleanly
        if (wifi_connected) {
            set_led(false);
        }
    }
}

// ----------------------------
// PUBLIC FUNCTIONS
// ----------------------------

void heartbeat_init(gpio_num_t led_gpio) {
    led_gpio_pin = led_gpio;
    gpio_reset_pin(led_gpio);
    gpio_set_direction(led_gpio, GPIO_MODE_OUTPUT);
    set_led(false);

    // Create timers
    esp_timer_create_args_t fast_args = {
        .callback = &fast_blink_cb,
        .name = "fast_heartbeat"
    };
    esp_timer_create(&fast_args, &fast_timer);

    esp_timer_create_args_t slow_on_args = {
        .callback = &slow_heartbeat_on_cb,
        .name = "slow_heartbeat_on"
    };
    esp_timer_create(&slow_on_args, &slow_timer_on);

    esp_timer_create_args_t slow_off_args = {
        .callback = &slow_heartbeat_off_cb,
        .name = "slow_heartbeat_off"
    };
    esp_timer_create(&slow_off_args, &slow_timer_off);

    esp_timer_create_args_t traffic_args = {
        .callback = &traffic_burst_cb,
        .name = "traffic_burst"
    };
    esp_timer_create(&traffic_args, &traffic_timer);

    // Start with fast heartbeat by default
    wifi_connected = false;
    esp_timer_start_periodic(fast_timer, FAST_INTERVAL_US);
}

void heartbeat_set_connected(bool connected) {
    if (wifi_connected == connected) return;

    wifi_connected = connected;

    if (connected) {
        // Stop fast blinking
        esp_timer_stop(fast_timer);

        // Start slow heartbeat
        set_led(false);
        esp_timer_start_periodic(slow_timer_on, SLOW_HEARTBEAT_PERIOD_US);
    } else {
        // Stop slow heartbeat
        esp_timer_stop(slow_timer_on);
        esp_timer_stop(slow_timer_off);

        // Make sure LED starts clean, start fast blink
        set_led(false);
        esp_timer_start_periodic(fast_timer, FAST_INTERVAL_US);
    }
}

void heartbeat_trigger_traffic_burst() {
    if (burst_active) return;  // Already active, skip
    burst_active = true;
    traffic_blink_count = 0;

    // Start first blink step immediately
    set_led(true);
    esp_timer_start_once(traffic_timer, TRAFFIC_ON_US);
}
