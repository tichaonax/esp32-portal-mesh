#ifndef HEARTBEAT_H
#define HEARTBEAT_H

#include "driver/gpio.h"
#include <stdbool.h>

void heartbeat_init(gpio_num_t led_gpio);
void heartbeat_set_connected(bool connected);
void heartbeat_trigger_traffic_burst();

#endif // HEARTBEAT_H
