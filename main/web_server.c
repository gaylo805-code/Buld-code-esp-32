#include "web_server.h"
#include "dns_sniffer.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "cJSON.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "WEB_SERVER";

// HTML content (sẽ được lưu trong file riêng hoặc Flash)
static const char *INDEX_HTML = 
"<!DOCTYPE html><html lang='vi'><head><meta charset='UTF-8'>"
"<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
"<title>DNS Sniffer Pro - ESP32 IDF</title>"
"<style>"
":root{--bg-primary:#0a0e27;--bg-secondary:#141832;--bg-card:#1a1f3a;"
"--text-primary:#e0e6ff;--text-secondary:#8892b0;--accent:#64ffda;"
"--accent2:#7c4dff;--danger:#ff5252;--success:#69f0ae;--warning:#ffd740;"
"--border:#2a2f4a}"
"*{margin:0;padding:0;box-sizing:border-box}"
"body{font-family:'Segoe UI',sans-serif;background:var(--bg-primary);"
"color:var(--text-primary);line-height:1.6}"
".container{max-width:1400px;margin:0 auto;padding:20px}"
".header{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);"
"padding:30px;border-radius:15px;margin-bottom:30px;"
"box-shadow:0 10px 40px rgba(102,126,234,0.3)}"
".header h1{font-size:2.5em;margin-bottom:10px;"
"text-shadow:2px 2px 4px rgba(0,0,0,0.3)}"
".stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));"
"gap:20px;margin-bottom:30px}"
".stat-card{background:var(--bg-card);padding:25px;border-radius:12px;"
"border:1px solid var(--border);transition:all 0.3s;position:relative;overflow:hidden}"
".stat-card:hover{transform:translateY(-5px);box-shadow:0 15px 30px rgba(0,0,0,0.3)}"
".stat-card::before{content:'';position:absolute;top:0;left:0;width:4px;"
"height:100%;background:var(--accent)}"
".stat-value{font-size:2.5em;font-weight:bold;color:var(--accent);margin:10px 0}"
".stat-label{color:var(--text-secondary);font-size:0.9em;text-transform:uppercase;"
"letter-spacing:1px}"
".controls-panel{background:var(--bg-card);padding:25px;border-radius:12px;"
"margin-bottom:30px;border:1px solid var(--border);display:flex;gap:15px;"
"flex-wrap:wrap;align-items:center}"
".btn{padding:12px 24px;border:none;border-radius:8px;font-size:1em;"
"cursor:pointer;transition:all 0.3s;font-weight:600;display:flex;"
"align-items:center;gap:8px}"
".btn-success{background:var(--success);color:var(--bg-primary)}"
".btn-danger{background:var(--danger);color:white}"
".btn-primary{background:var(--accent2);color:white}"
".btn:hover{transform:scale(1.05);box-shadow:0 5px 15px rgba(0,0,0,0.3)}"
".table-container{background:var(--bg-card);border-radius:12px;"
"border:1px solid var(--border);overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,0.2)}"
"table{width:100%;border-collapse:collapse}"
"thead{background:var(--bg-secondary)}"
"th{padding:15px;text-align:left;font-weight:600;color:var(--accent);"
"text-transform:uppercase;font-size:0.85em;letter-spacing:1px}"
"td{padding:15px;border-bottom:1px solid var(--border)}"
"tbody tr:hover{background:var(--bg-secondary)}"
".badge{padding:5px 10px;border-radius:20px;font-size:0.8em;font-weight:600}"
".badge-danger{background:rgba(255,82,82,0.1);color:var(--danger);"
"border:1px solid var(--danger)}"
".badge-success{background:rgba(105,240,174,0.1);color:var(--success);"
"border:1px solid var(--success)}"
".domain{color:var(--accent);font-weight:500}"
"@media(max-width:768px){.header h1{font-size:1.8em}}"
"</style></head><body><div class='container'>"
"<div class='header'><h1>🔍 DNS Sniffer Pro</h1>"
"<p>ESP32 IDF - DNS Packet Analyzer</p></div>"
"<div class='stats-grid'>"
"<div class='stat-card'><div class='stat-label'>Tổng gói tin</div>"
"<div class='stat-value' id='totalPackets'>0</div></div>"
"<div class='stat-card'><div class='stat-label'>Đã chặn</div>"
"<div class='stat-value' id='blockedPackets'>0</div></div>"
"<div class='stat-card'><div class='stat-label'>Domain duy nhất</div>"
"<div class='stat-value' id='uniqueDomains'>0</div></div>"
"<div class='stat-card'><div class='stat-label'>Trạng thái</div>"
"<div class='stat-value' id='captureStatus'>Đang bắt</div></div></div>"
"<div class='controls-panel'>"
"<button class='btn btn-success' onclick='toggleCapture()'>⏸️ Tạm dừng</button>"
"<button class='btn btn-danger' onclick='clearAll()'>🗑️ Xóa tất cả</button>"
"<button class='btn btn-primary' onclick='exportData()'>📥 Xuất JSON</button></div>"
"<div class='table-container'><div style='max-height:600px;overflow-y:auto'>"
"<table><thead><tr><th>#</th><th>Thời gian</th><th>Nguồn</th>"
"<th>Domain</th><th>Loại</th><th>IP Đích</th><th>Trạng thái</th></tr></thead>"
"<tbody id='packetsTable'><tr><td colspan='7' style='text-align:center;padding:20px'>"
"Đang chờ gói tin DNS...</td></tr></tbody></table></div></div></div>"
"<script>"
"async function fetchData(){"
"try{const r=await fetch('/api/packets');const d=await r.json();updateUI(d)}"
"catch(e){console.error(e)}}"
"function updateUI(d){"
"document.getElementById('totalPackets').textContent=d.total;"
"document.getElementById('blockedPackets').textContent=d.blocked;"
"document.getElementById('uniqueDomains').textContent=d.uniqueDomains;"
"const s=document.getElementById('captureStatus');"
"if(d.captureEnabled){s.textContent='Đang bắt';s.style.color='var(--success)'}"
"else{s.textContent='Đã dừng';s.style.color='var(--danger)'}"
"updateTable(d.packets)}"
"function updateTable(p){"
"const t=document.getElementById('packetsTable');"
"if(!p||p.length===0){t.innerHTML='<tr><td colspan=\"7\" style=\"text-align:center\">"
"Đang chờ gói tin...</td></tr>';return}"
"t.innerHTML=p.reverse().map((x,i)=>`<tr><td><span class='badge'>#${x.id}</span></td>"
"<td>${x.timestamp}</td><td><span class='badge'>${x.srcIP}</span></td>"
"<td><span class='domain'>${x.domain||'N/A'}</span></td>"
"<td><span class='badge'>${x.queryType}</span></td><td>${x.responseIP||'...'}</td>"
"<td>${x.isBlocked?'<span class=\"badge badge-danger\">🚫 Đã chặn</span>':"
"'<span class=\"badge badge-success\">✅ Cho phép</span>'}</td></tr>`).join('')}"
"async function toggleCapture(){"
"await fetch('/api/toggle');fetchData()}"
"async function clearAll(){if(confirm('Xóa tất cả?'))"
"{await fetch('/api/clear');fetchData()}}"
"async function exportData(){"
"const r=await fetch('/api/packets');const d=await r.json();"
"const b=new Blob([JSON.stringify(d,null,2)],{type:'application/json'});"
"const u=URL.createObjectURL(b);const a=document.createElement('a');"
"a.href=u;a.download=`dns-packets-${Date.now()}.json`;a.click()}"
"document.addEventListener('DOMContentLoaded',()=>{fetchData();"
"setInterval(fetchData,2000)});"
"</script></body></html>";

// API Handler: Lấy danh sách gói tin
static esp_err_t api_get_packets_handler(httpd_req_t *req)
{
    dns_packet_t packets[100];
    int count = dns_sniffer_get_packets(packets, 100);
    dns_statistics_t *stats = dns_sniffer_get_stats();
    
    cJSON *root = cJSON_CreateObject();
    cJSON *packets_array = cJSON_CreateArray();
    
    for (int i = 0; i < count; i++) {
        cJSON *packet = cJSON_CreateObject();
        cJSON_AddNumberToObject(packet, "id", packets[i].id);
        cJSON_AddStringToObject(packet, "timestamp", packets[i].timestamp);
        cJSON_AddStringToObject(packet, "srcIP", packets[i].src_ip);
        cJSON_AddStringToObject(packet, "domain", packets[i].domain);
        cJSON_AddStringToObject(packet, "queryType", packets[i].query_type);
        cJSON_AddStringToObject(packet, "responseIP", packets[i].response_ip);
        cJSON_AddBoolToObject(packet, "isBlocked", packets[i].is_blocked);
        cJSON_AddItemToArray(packets_array, packet);
    }
    
    cJSON_AddItemToObject(root, "packets", packets_array);
    cJSON_AddNumberToObject(root, "total", stats->total_packets);
    cJSON_AddNumberToObject(root, "blocked", stats->blocked_packets);
    cJSON_AddNumberToObject(root, "uniqueDomains", stats->unique_domains);
    cJSON_AddBoolToObject(root, "captureEnabled", stats->capture_enabled);
    
    char *json_str = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_str, strlen(json_str));
    
    free(json_str);
    cJSON_Delete(root);
    
    return ESP_OK;
}

// API Handler: Toggle bắt/tạm dừng
static esp_err_t api_toggle_handler(httpd_req_t *req)
{
    dns_statistics_t *stats = dns_sniffer_get_stats();
    dns_sniffer_toggle(!stats->capture_enabled);
    
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", 
                           stats->capture_enabled ? "started" : "stopped");
    
    char *json_str = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_str, strlen(json_str));
    
    free(json_str);
    cJSON_Delete(root);
    
    return ESP_OK;
}

// API Handler: Xóa tất cả
static esp_err_t api_clear_handler(httpd_req_t *req)
{
    dns_sniffer_clear();
    
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "cleared");
    
    char *json_str = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_str, strlen(json_str));
    
    free(json_str);
    cJSON_Delete(root);
    
    return ESP_OK;
}

// API Handler: Chặn domain
static esp_err_t api_block_handler(httpd_req_t *req)
{
    char domain[256] = {0};
    
    // Lấy tham số domain từ query string
    size_t buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1) {
        char *buf = malloc(buf_len);
        if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
            char param[32];
            if (httpd_query_key_value(buf, "domain", param, sizeof(param)) == ESP_OK) {
                strncpy(domain, param, sizeof(domain) - 1);
            }
        }
        free(buf);
    }
    
    bool success = false;
    if (strlen(domain) > 0) {
        success = dns_sniffer_block_domain(domain);
    }
    
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "success", success);
    cJSON_AddStringToObject(root, "domain", domain);
    
    char *json_str = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_str, strlen(json_str));
    
    free(json_str);
    cJSON_Delete(root);
    
    return ESP_OK;
}

// Handler cho trang chính
static esp_err_t index_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, INDEX_HTML, strlen(INDEX_HTML));
    return ESP_OK;
}

// Cấu hình URI handlers
static const httpd_uri_t uri_handlers[] = {
    {
        .uri = "/",
        .method = HTTP_GET,
        .handler = index_handler,
        .user_ctx = NULL
    },
    {
        .uri = "/api/packets",
        .method = HTTP_GET,
        .handler = api_get_packets_handler,
        .user_ctx = NULL
    },
    {
        .uri = "/api/toggle",
        .method = HTTP_GET,
        .handler = api_toggle_handler,
        .user_ctx = NULL
    },
    {
        .uri = "/api/clear",
        .method = HTTP_GET,
        .handler = api_clear_handler,
        .user_ctx = NULL
    },
    {
        .uri = "/api/block",
        .method = HTTP_GET,
        .handler = api_block_handler,
        .user_ctx = NULL
    }
};

void web_server_init(void)
{
    ESP_LOGI(TAG, "🌐 Khởi tạo Web Server...");
    
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 16;
    config.lru_purge_enable = true;
    
    // Khởi động HTTP server
    if (httpd_start(&server, &config) == ESP_OK) {
        // Đăng ký URI handlers
        for (int i = 0; i < sizeof(uri_handlers) / sizeof(uri_handlers[0]); i++) {
            httpd_register_uri_handler(server, &uri_handlers[i]);
        }
        
        ESP_LOGI(TAG, "✅ Web Server đã khởi động trên port %d", config.server_port);
        ESP_LOGI(TAG, "🌐 Truy cập: http://192.168.4.1");
    } else {
        ESP_LOGE(TAG, "❌ Không thể khởi động Web Server!");
    }
}
