#ifndef DNS_SNIFFER_H
#define DNS_SNIFFER_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// Cấu trúc gói tin DNS
typedef struct {
    uint32_t id;
    char timestamp[32];
    char src_ip[16];
    char dst_ip[16];
    char domain[256];
    char query_type[8];
    char response_ip[16];
    bool is_blocked;
} dns_packet_t;

// Cấu trúc thống kê
typedef struct {
    uint32_t total_packets;
    uint32_t blocked_packets;
    uint32_t unique_domains;
    bool capture_enabled;
} dns_statistics_t;

/**
 * @brief Khởi tạo DNS Sniffer
 */
void dns_sniffer_init(void);

/**
 * @brief Bắt đầu/Tạm dừng bắt gói tin
 * @param enable true: bắt đầu, false: tạm dừng
 */
void dns_sniffer_toggle(bool enable);

/**
 * @brief Lấy thống kê
 * @return Con trỏ đến cấu trúc thống kê
 */
dns_statistics_t *dns_sniffer_get_stats(void);

/**
 * @brief Lấy danh sách gói tin
 * @param packets Mảng chứa gói tin
 * @param max_count Số lượng tối đa
 * @return Số lượng thực tế
 */
int dns_sniffer_get_packets(dns_packet_t *packets, int max_count);

/**
 * @brief Chặn domain
 * @param domain Tên domain cần chặn
 * @return true nếu thành công
 */
bool dns_sniffer_block_domain(const char *domain);

/**
 * @brief Bỏ chặn domain
 * @param domain Tên domain cần bỏ chặn
 * @return true nếu thành công
 */
bool dns_sniffer_unblock_domain(const char *domain);

/**
 * @brief Kiểm tra domain có bị chặn không
 * @param domain Tên domain
 * @return true nếu bị chặn
 */
bool dns_sniffer_is_blocked(const char *domain);

/**
 * @brief Lấy danh sách domain bị chặn
 * @param domains Mảng chứa domain
 * @param max_count Số lượng tối đa
 * @return Số lượng thực tế
 */
int dns_sniffer_get_blocked_domains(char domains[][256], int max_count);

/**
 * @brief Xóa tất cả gói tin
 */
void dns_sniffer_clear(void);

#endif // DNS_SNIFFER_H
