#!/bin/bash
# setup_lan.sh - Khoi tao mang LAN 10.0.0.0/24 co Switch ao (Bridge) va 5 may con
set -e

echo "[*] Dang don dep topo cu neu co..."
for ns in h1 h2 atk vic amp1 amp2 amp3; do
    ip netns del $ns 2>/dev/null || true
done
ip link del br0 2>/dev/null || true

echo "[*] Dang tao switch ao br0 (Linux Bridge)..."
ip link add br0 type bridge
ip link set br0 up

add_host() {
    ns=$1; ipaddr=$2
    ip netns add $ns
    # Tao cap day noi giua may con va switch br0
    ip link add ${ns}0 type veth peer name ${ns}-br
    ip link set ${ns}-br master br0
    ip link set ${ns}-br up
    ip link set ${ns}0 netns $ns
    ip netns exec $ns ip addr add ${ipaddr}/24 dev ${ns}0
    ip netns exec $ns ip link set ${ns}0 up
    ip netns exec $ns ip link set lo up
}

echo "[*] Dang khoi tao 5 may con doc lap:"
add_host atk  10.0.0.100      # May ke tan cong (Attacker)
add_host vic  10.0.0.200      # May nan nhan (Victim)
add_host amp1 10.0.0.11       # May khuech dai 1
add_host amp2 10.0.0.12       # May khuech dai 2
add_host amp3 10.0.0.13       # May khuech dai 3

echo "[*] Cau hinh mo lo hong tren cac may khuech dai (cho phep tra loi ping broadcast)..."
for h in amp1 amp2 amp3; do
    ip netns exec $h sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=0 >/dev/null 2>&1
done

echo ""
echo "=================================================================="
echo "[+] MANG LAN 10.0.0.0/24 (Broadcast: 10.0.0.255) DA SAN SANG!"
echo "    - Kẻ tấn công (atk): 10.0.0.100"
echo "    - Nạn nhân (vic):    10.0.0.200"
echo "    - Khuếch đại 1-3:    10.0.0.11, 10.0.0.12, 10.0.0.13"
echo "=================================================================="

