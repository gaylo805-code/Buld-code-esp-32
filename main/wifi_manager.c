#include "wifi_manager.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "freertos/event_groups.h"

static const char *TAG = "WIFI_MANAGER";
static int s_connected_clients = 0;

// Event group để đồng bộ WiFi
static EventGroupHandle_t wifi_event_group;
const int WIFI_CONNECTED_BIT = BIT0;

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT) {
        switch (event_id) {
            case WIFI_EVENT_AP_STACONNECTED: {
                wifi_event_ap_staconnected_t *event = 
                    (wifi_event_ap_staconnected_t *)event_data;
                ESP_LOGI(TAG, "📱 Client kết nối: " MACSTR, MAC2STR(event->mac));
                s_connected_clients++;
                break;
            }
            case WIFI_EVENT_AP_STADISCONNECTED: {
                wifi_event_ap_stadisconnected_t *event = 
                    (wifi_event_ap_stadisconnected_t *)event_data;
                ESP_LOGI(TAG, "📱 Client ngắt kết nối: " MACSTR, MAC2STR(event->mac));
                s_connected_clients--;
                break;
            }
            default:
                break;
        }
    }
}

void wifi_init_softap(void)
{
    ESP_LOGI(TAG, "🔄 Khởi tạo WiFi Access Point...");

    // Tạo event group
    wifi_event_group = xEventGroupCreate();

    // Khởi tạo WiFi
    ESP_ERROR_CHECK(esp_netif_init());
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // Đăng ký event handler
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT,
        ESP_EVENT_ANY_ID,
        &wifi_event_handler,
        NULL,
        NULL
    ));

    // Cấu hình WiFi AP
    wifi_config_t wifi_config = {
        .ap = {
            .ssid = WIFI_SSID,
            .ssid_len = strlen(WIFI_SSID),
            .channel = WIFI_CHANNEL,
            .password = WIFI_PASSWORD,
            .max_connection = WIFI_MAX_CONN,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {
                .required = false,
            },
        },
    };

    // Nếu không có mật khẩu
    if (strlen(WIFI_PASSWORD) == 0) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    // Set mode AP
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "✅ WiFi AP đã khởi động");
    ESP_LOGI(TAG, "📡 SSID: %s", WIFI_SSID);
    ESP_LOGI(TAG, "🔑 Password: %s", WIFI_PASSWORD);
}

int wifi_get_connected_clients(void)
{
    return s_connected_clients;
}
