#!/bin/bash
# setup_dns.sh - Khoi tao mo hinh mang cho Bai Lab 07 (DNSSEC)
set -e

echo "[*] 1. Don dep cac tien trinh va namespace cu..."
pkill -f named 2>/dev/null || true
pkill -f unbound 2>/dev/null || true
for ns in dns-auth dns-res client rogue vic gw atk dst amp1 amp2 amp3 h1 h2; do
    ip netns del $ns 2>/dev/null || true
done
ip link del br0 2>/dev/null || true

echo "[*] 2. Tao Switch ao br0 (Linux Bridge) cho mang LAN 10.0.0.0/24..."
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

echo "[*] 3. Khoi tao 4 may trong mang LAN 10.0.0.0/24:"
add_host dns-auth 10.0.0.2      # May chu uy quyen (BIND9, CO ky DNSSEC)
add_host dns-res  10.0.0.3      # Resolver kiem tra DNSSEC (Unbound)
add_host client   10.0.0.4      # May khach truy van (dig)
add_host rogue    10.0.0.66     # May chu DNS gia mao (BIND9, KHONG ky)

echo ""
echo "=================================================================="
echo "[+] MO HINH MANG CHO LAB 07 DA SAN SANG!"
echo "    - Mạng LAN chung:       10.0.0.0/24 qua switch br0"
echo "    - dns-auth (10.0.0.2):  Máy chủ Authoritative DNS có ký DNSSEC"
echo "    - dns-res  (10.0.0.3):  Validating Recursive Resolver (Unbound)"
echo "    - client   (10.0.0.4):  Máy trạm kiểm thử (Client truy vấn dig)"
echo "    - rogue    (10.0.0.66): Máy chủ DNS giả mạo (Không có DNSSEC)"
echo "=================================================================="
echo "[*] Kiem tra ket noi: client ping sang dns-auth va dns-res:"
ip netns exec client ping -c 1 10.0.0.2
ip netns exec client ping -c 1 10.0.0.3
echo "[+] Ping thanh cong! San sang cho cac buoc tiep theo."

