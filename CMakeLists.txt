cmake_minimum_required(VERSION 3.5)

# ESP-IDF v4.1 yêu cầu CMake 3.5+
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Không sử dụng EXTRA_COMPONENT_DIRS trong IDF v4.1
project(dns_sniffer)
