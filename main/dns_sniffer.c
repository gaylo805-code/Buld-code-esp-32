#include "dns_sniffer.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

static const char *TAG = "DNS_SNIFFER";

#define MAX_PACKETS         1000
#define MAX_BLOCKED_DOMAINS 100
#define DNS_PORT            53
#define BUFFER_SIZE         1024

// Biến toàn cục
static dns_packet_t s_packets[MAX_PACKETS];
static int s_packet_count = 0;
static char s_blocked_domains[MAX_BLOCKED_DOMAINS][256];
static int s_blocked_count = 0;
static dns_statistics_t s_stats = {0};
static SemaphoreHandle_t s_mutex = NULL;
static TaskHandle_t s_dns_task = NULL;

// Domain mẫu cho demo (trong thực tế sẽ bắt từ gói tin thật)
static const char *sample_domains[] = {
    "google.com", "facebook.com", "youtube.com", "github.com",
    "stackoverflow.com", "amazon.com", "netflix.com", "twitter.com",
    "instagram.com", "linkedin.com", "reddit.com", "wikipedia.org",
    "microsoft.com", "apple.com", "spotify.com", "discord.com",
    "twitch.tv", "whatsapp.com", "telegram.org", "zoom.us",
    "tiktok.com", "pinterest.com", "snapchat.com", "quora.com",
    "medium.com", "dropbox.com", "slack.com", "notion.so"
};

static int sample_domain_count = sizeof(sample_domains) / sizeof(sample_domains[0]);

static void dns_capture_task(void *arg)
{
    ESP_LOGI(TAG, "🔄 DNS Capture Task started");
    
    // Trong thực tế, đây sẽ là nơi đọc gói tin DNS thật
    // từ network interface sử dụng promiscuous mode
    
    while (1) {
        if (s_stats.capture_enabled) {
            // Giả lập bắt gói tin (demo)
            if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
                if (s_packet_count < MAX_PACKETS) {
                    // Tạo gói tin mới
                    dns_packet_t *pkt = &s_packets[s_packet_count];
                    pkt->id = s_packet_count + 1;
                    
                    // Timestamp
                    time_t now;
                    struct tm timeinfo;
                    time(&now);
                    localtime_r(&now, &timeinfo);
                    strftime(pkt->timestamp, sizeof(pkt->timestamp), 
                            "%H:%M:%S", &timeinfo);
                    
                    // IP nguồn giả lập
                    snprintf(pkt->src_ip, sizeof(pkt->src_ip), 
                            "192.168.4.%d", (rand() % 200) + 2);
                    
                    // Domain ngẫu nhiên
                    int domain_idx = rand() % sample_domain_count;
                    strncpy(pkt->domain, sample_domains[domain_idx], 
                            sizeof(pkt->domain) - 1);
                    
                    // Query type
                    strcpy(pkt->query_type, (rand() % 2 == 0) ? "A" : "AAAA");
                    
                    // Kiểm tra domain có bị chặn không
                    pkt->is_blocked = dns_sniffer_is_blocked(pkt->domain);
                    
                    if (pkt->is_blocked) {
                        strcpy(pkt->response_ip, "0.0.0.0");
                        s_stats.blocked_packets++;
                    } else {
                        snprintf(pkt->response_ip, sizeof(pkt->response_ip),
                                "%d.%d.%d.%d",
                                rand() % 255 + 1, rand() % 255 + 1,
                                rand() % 255 + 1, rand() % 255 + 1);
                    }
                    
                    s_packet_count++;
                    s_stats.total_packets++;
                    
                    // Đếm unique domains
                    bool found = false;
                    for (int i = 0; i < s_packet_count - 1; i++) {
                        if (strcmp(s_packets[i].domain, pkt->domain) == 0) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        s_stats.unique_domains++;
                    }
                }
                xSemaphoreGive(s_mutex);
            }
        }
        
        // Delay ngẫu nhiên 1-3 giây để giả lập traffic
        int delay_ms = 1000 + (rand() % 2000);
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
    }
}

void dns_sniffer_init(void)
{
    ESP_LOGI(TAG, "🔧 Khởi tạo DNS Sniffer...");
    
    // Tạo mutex
    s_mutex = xSemaphoreCreateMutex();
    if (s_mutex == NULL) {
        ESP_LOGE(TAG, "❌ Không thể tạo mutex!");
        return;
    }
    
    // Khởi tạo random seed
    srand(esp_timer_get_time());
    
    // Khởi tạo thống kê
    memset(&s_stats, 0, sizeof(s_stats));
    s_stats.capture_enabled = true;
    
    // Tạo task bắt gói tin
    xTaskCreate(
        dns_capture_task,
        "dns_capture",
        4096,
        NULL,
        5,
        &s_dns_task
    );
    
    ESP_LOGI(TAG, "✅ DNS Sniffer đã khởi động");
}

void dns_sniffer_toggle(bool enable)
{
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        s_stats.capture_enabled = enable;
        xSemaphoreGive(s_mutex);
        ESP_LOGI(TAG, "%s bắt gói tin DNS", enable ? "▶️ Bắt đầu" : "⏸️ Tạm dừng");
    }
}

dns_statistics_t *dns_sniffer_get_stats(void)
{
    return &s_stats;
}

int dns_sniffer_get_packets(dns_packet_t *packets, int max_count)
{
    int count = 0;
    
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        int start_idx = s_packet_count > max_count ? 
                       s_packet_count - max_count : 0;
        
        for (int i = start_idx; i < s_packet_count && count < max_count; i++) {
            memcpy(&packets[count], &s_packets[i], sizeof(dns_packet_t));
            count++;
        }
        
        xSemaphoreGive(s_mutex);
    }
    
    return count;
}

bool dns_sniffer_block_domain(const char *domain)
{
    if (s_blocked_count >= MAX_BLOCKED_DOMAINS) {
        ESP_LOGW(TAG, "⚠️ Đã đạt giới hạn domain bị chặn");
        return false;
    }
    
    if (dns_sniffer_is_blocked(domain)) {
        ESP_LOGW(TAG, "⚠️ Domain %s đã bị chặn", domain);
        return false;
    }
    
    strncpy(s_blocked_domains[s_blocked_count], domain, 255);
    s_blocked_domains[s_blocked_count][255] = '\0';
    s_blocked_count++;
    
    ESP_LOGI(TAG, "🚫 Đã chặn domain: %s", domain);
    return true;
}

bool dns_sniffer_unblock_domain(const char *domain)
{
    for (int i = 0; i < s_blocked_count; i++) {
        if (strcmp(s_blocked_domains[i], domain) == 0) {
            // Xóa domain khỏi danh sách
            for (int j = i; j < s_blocked_count - 1; j++) {
                strcpy(s_blocked_domains[j], s_blocked_domains[j + 1]);
            }
            s_blocked_count--;
            ESP_LOGI(TAG, "✅ Đã bỏ chặn domain: %s", domain);
            return true;
        }
    }
    
    ESP_LOGW(TAG, "⚠️ Domain %s không có trong danh sách chặn", domain);
    return false;
}

bool dns_sniffer_is_blocked(const char *domain)
{
    for (int i = 0; i < s_blocked_count; i++) {
        if (strcmp(s_blocked_domains[i], domain) == 0) {
            return true;
        }
    }
    return false;
}

int dns_sniffer_get_blocked_domains(char domains[][256], int max_count)
{
    int count = s_blocked_count < max_count ? s_blocked_count : max_count;
    
    for (int i = 0; i < count; i++) {
        strncpy(domains[i], s_blocked_domains[i], 255);
        domains[i][255] = '\0';
    }
    
    return count;
}

void dns_sniffer_clear(void)
{
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        memset(s_packets, 0, sizeof(s_packets));
        s_packet_count = 0;
        s_stats.total_packets = 0;
        s_stats.blocked_packets = 0;
        s_stats.unique_domains = 0;
        xSemaphoreGive(s_mutex);
        
        ESP_LOGI(TAG, "🗑️ Đã xóa tất cả gói tin");
    }
}
