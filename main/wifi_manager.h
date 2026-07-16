#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H

#include "esp_err.h"

// Cấu hình WiFi AP
#define WIFI_SSID           "DNS_Sniffer_Pro"
#define WIFI_PASSWORD       "dns12345678"
#define WIFI_MAX_CONN       10
#define WIFI_CHANNEL        1

/**
 * @brief Khởi tạo WiFi Access Point
 */
void wifi_init_softap(void);

/**
 * @brief Lấy danh sách client đã kết nối
 * @return Số lượng client
 */
int wifi_get_connected_clients(void);

#endif // WIFI_MANAGER_H
