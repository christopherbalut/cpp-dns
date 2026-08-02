#!/usr/bin/env bash
set -euo pipefail

cmake --build build

sudo install -Dm755 build/cpp_dns_app /usr/local/bin/cpp_dns_app

sudo mkdir -p /etc/cpp-dns

if [ ! -f /etc/cpp-dns/config.conf ]; then
    sudo install -Dm644 packaging/config.conf /etc/cpp-dns/config.conf
fi

if [ ! -f /etc/cpp-dns/blocklist.txt ]; then
    sudo install -Dm644 blocklist.txt /etc/cpp-dns/blocklist.txt
fi

if [ ! -f /etc/cpp-dns/allowlist.txt ]; then
    sudo install -Dm644 allowlist.txt /etc/cpp-dns/allowlist.txt
fi

sudo install -Dm544 packaging/cpp-dns.service /etc/systemd/system/cpp-dns.service

sudo systemctl daemon-reload

echo "cpp-dns installed"
echo "Start with: sudo systemctl start cpp-dns"
echo "Enable on boot with: sudo systemctl enable cpp-dns"
