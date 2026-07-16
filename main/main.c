#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"

#include "wifi_manager.h"
#include "dns_sniffer.h"
#include "web_server.h"

static const char *TAG = "DNS_SNIFFER_MAIN";

void app_main(void)
{
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "🔍 DNS Sniffer Pro - ESP32 (IDF)");
    ESP_LOGI(TAG, "========================================");

    // Khởi tạo NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Khởi tạo TCP/IP stack
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Khởi tạo WiFi AP
    wifi_init_softap();

    // Khởi tạo DNS Sniffer
    dns_sniffer_init();

    // Khởi tạo Web Server
    web_server_init();

    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "🌟 Hệ thống đã sẵn sàng!");
    ESP_LOGI(TAG, "📱 SSID: DNS_Sniffer_Pro");
    ESP_LOGI(TAG, "🔑 Password: dns12345678");
    ESP_LOGI(TAG, "🌐 Truy cập: http://192.168.4.1");
    ESP_LOGI(TAG, "========================================");

    // Task chính không làm gì, các task khác xử lý
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
