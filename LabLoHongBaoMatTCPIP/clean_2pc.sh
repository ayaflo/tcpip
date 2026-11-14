#!/bin/bash
# clean_2pc.sh - Don dep ha tang mang 2 may laptop (xoa vxlan, bridge va namespace)
echo "[*] Dang don dep toan bo cau hinh mang 2 may..."
ip link del vxlan0 2>/dev/null || true
ip link del br0 2>/dev/null || true

for ns in h1 h2 vic gw atk dst amp1 amp2 amp3 client dns-auth dns-res rogue; do
    ip netns del $ns 2>/dev/null || true
done

pkill -9 -f "named" 2>/dev/null || true
pkill -9 -f "unbound" 2>/dev/null || true

echo "[+] Da don dep xong toan bo tren may nay!"
