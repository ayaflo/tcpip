#!/bin/bash
# clean_redirect.sh - Don dep topo Lab 05 sau khi hoan thanh
echo "[*] Dang don dep cac namespace va bridge br0..."
for ns in vic gw atk dst; do
    ip netns del $ns 2>/dev/null || true
done
ip link del br0 2>/dev/null || true
echo "[+] Da don dep xong!"

