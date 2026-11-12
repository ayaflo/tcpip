#!/bin/bash
# clean_lan.sh - Don dep mang LAN ao sau khi hoan thanh Bai 4
echo "[*] Dang don dep cac namespace va bridge br0..."
for ns in atk vic amp1 amp2 amp3; do
    ip netns del $ns 2>/dev/null || true
done
ip link del br0 2>/dev/null || true
echo "[+] Da don dep xong!"

