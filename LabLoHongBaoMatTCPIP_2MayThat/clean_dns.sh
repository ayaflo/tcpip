#!/bin/bash
# clean_dns.sh - Don dep moi truong sau khi thuc hanh Lab 07
echo "[*] Dang dung cac tien trinh named va unbound..."
pkill -9 -f named 2>/dev/null || true
pkill -9 -f unbound 2>/dev/null || true

echo "[*] Dang xoa cac namespace va bridge..."
for ns in dns-auth dns-res client rogue; do
    ip netns del $ns 2>/dev/null || true
done
ip link del br0 2>/dev/null || true

echo "[*] Don dep cac file tam..."
rm -f /tmp/named-auth.conf /tmp/named-rogue.conf /tmp/unbound.conf /tmp/trust-anchor.key /tmp/lab.dnskey /tmp/unbound.pid 2>/dev/null || true
rm -f /etc/bind/named-auth.conf /etc/bind/named-rogue.conf /etc/unbound/unbound.conf /etc/unbound/trust-anchor.key 2>/dev/null || true

echo "[+] Da don dep xong moi truong Lab 07!"
