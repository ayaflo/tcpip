#!/bin/bash
# clean_pair.sh - Don dep moi truong sau khi thuc hanh Lab 06
echo "[*] Dang don dep cac namespace h1, h2..."
for ns in h1 h2 vic gw atk dst amp1 amp2 amp3; do
    ip netns del $ns 2>/dev/null || true
done
ip link del br0 2>/dev/null || true
echo "[+] Da don dep xong!"

