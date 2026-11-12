#!/bin/bash
# setup_redirect.sh - Khoi tao mo hinh mang cho Bai Lab 05 (ICMP Redirect Attack)
set -e

echo "[*] Dang don dep topo cu neu co..."
for ns in vic gw atk dst amp1 amp2 amp3 h1 h2; do
    ip netns del $ns 2>/dev/null || true
done
ip link del br0 2>/dev/null || true

echo "[*] 1. Tao Switch ao br0 (Linux Bridge) cho mang LAN 10.0.0.0/24..."
ip link add br0 type bridge
ip link set br0 up

add_host() {
    ns=$1; ipaddr=$2
    ip netns add $ns
    ip link add ${ns}0 type veth peer name ${ns}-br
    ip link set ${ns}-br master br0
    ip link set ${ns}-br up
    ip link set ${ns}0 netns $ns
    ip netns exec $ns ip addr add ${ipaddr}/24 dev ${ns}0
    ip netns exec $ns ip link set ${ns}0 up
    ip netns exec $ns ip link set lo up
}

echo "[*] 2. Khoi tao 3 may trong mang LAN 10.0.0.0/24:"
add_host vic 10.0.0.2       # May nan nhan (Victim)
add_host gw  10.0.0.1       # Router Gateway hop phap
add_host atk 10.0.0.66      # May ke tan cong (Attacker cung LAN)

echo "[*] 3. Khoi tao mang dich 10.0.1.0/24 nam sau Router Gateway..."
ip netns add dst            # May dich (Destination Server)
ip link add gw-d type veth peer name d-gw
ip link set gw-d netns gw
ip link set d-gw netns dst

ip netns exec gw  ip addr add 10.0.1.254/24 dev gw-d
ip netns exec gw  ip link set gw-d up
ip netns exec dst ip addr add 10.0.1.5/24   dev d-gw
ip netns exec dst ip link set d-gw up
ip netns exec dst ip link set lo up

echo "[*] 4. Cau hinh chuyen tiep tren Router GW (tat send_redirects cua kernel)..."
ip netns exec gw sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
ip netns exec gw sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1
ip netns exec gw sysctl -w net.ipv4.conf.default.send_redirects=0 >/dev/null 2>&1

echo "[*] 5. Thiet lap dinh tuyen (Default Gateway)..."
ip netns exec vic ip route add default via 10.0.0.1
ip netns exec dst ip route add default via 10.0.1.254

echo "[*] 6. Mo lo hong tren Victim (chap nhan goi ICMP Redirect)..."
for k in all vic0; do
    ip netns exec vic sysctl -w net.ipv4.conf.$k.accept_redirects=1 >/dev/null 2>&1
    ip netns exec vic sysctl -w net.ipv4.conf.$k.secure_redirects=0 >/dev/null 2>&1
done

# Cho phep atk chuyen tiep goi tin (de lam MITM day du neu can)
ip netns exec atk sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

echo ""
echo "=================================================================="
echo "[+] TOPO MANG CHO LAB 05 DA SAN SANG!"
echo "    - Mạng LAN:          10.0.0.0/24"
echo "      + Gateway hợp pháp (gw): 10.0.0.1"
echo "      + Nạn nhân (vic):        10.0.0.2"
echo "      + Kẻ tấn công (atk):     10.0.0.66"
echo "    - Mạng đích phía sau GW:   10.0.1.0/24"
echo "      + Máy chủ đích (dst):    10.0.1.5"
echo "=================================================================="
echo "[*] Kiem tra ket noi ban dau: Victim ping sang Destination (10.0.1.5):"
ip netns exec vic ping -c 2 10.0.1.5

