#!/bin/bash
# Script cài đặt ESP-IDF v4.1 cho GitHub Actions

set -e

echo "🔧 Cài đặt ESP-IDF v4.1 với Python 3.8..."

# Kiểm tra Python version
python3 --version

# Cài đặt dependencies
pip3 install --upgrade pip setuptools wheel
pip3 install --user -r requirements.txt

# Clone ESP-IDF v4.1
if [ ! -d "$HOME/esp/esp-idf" ]; then
    echo "📥 Đang tải ESP-IDF v4.1..."
    mkdir -p $HOME/esp
    cd $HOME/esp
    git clone --branch v4.1 --recursive --depth 1 \
        https://github.com/espressif/esp-idf.git
else
    echo "✅ ESP-IDF đã tồn tại"
fi

# Cài đặt ESP32 tools
cd $HOME/esp/esp-idf
./install.sh esp32

echo "✅ Cài đặt hoàn tất!"
