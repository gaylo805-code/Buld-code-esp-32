# IDF v4.1 style
set(COMPONENT_SRCS
    "main.c"
    "dns_sniffer.c"
    "web_server.c"
    "wifi_manager.c"
)

set(COMPONENT_ADD_INCLUDEDIRS ".")

# Register component
idf_component_register(
    SRCS ${COMPONENT_SRCS}
    INCLUDE_DIRS ${COMPONENT_ADD_INCLUDEDIRS}
    REQUIRES 
        nvs_flash
        esp_wifi
        esp_netif
        esp_event
        esp_http_server
        lwip
        esp_timer
)

# cJSON được tích hợp sẵn trong IDF v4.1
