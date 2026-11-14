#!/bin/bash
# setup_lab5_2pc.sh - Trien khai Lab 05 (ICMP Redirect Attack) tren 2 Laptop Kali Linux (cung Wi-Fi)
set -e

ROLE=$1
REMOTE_IP=$2

if [ "$ROLE" != "host" ] && [ "$ROLE" != "attacker" ] || [ -z "$REMOTE_IP" ]; then
    echo "=================================================================="
    echo "HUONG DAN SU DUNG CHO 2 LAPTOP (LAB 05 - ICMP REDIRECT ATTACK):"
    echo "------------------------------------------------------------------"
    echo "1. Tren Laptop 1 (May Nan nhan vic + Gateway gw + Server dich dst):"
    echo "   sudo bash setup_lab5_2pc.sh host <IP_KALI_LAPTOP_2>"
    echo "   Vi du: sudo bash setup_lab5_2pc.sh host 192.168.1.20"
    echo ""
    echo "2. Tren Laptop 2 (May Ke tan cong - Attacker):"
    echo "   sudo bash setup_lab5_2pc.sh attacker <IP_KALI_LAPTOP_1>"
    echo "   Vi du: sudo bash setup_lab5_2pc.sh attacker 192.168.1.10"
    echo "=================================================================="
    exit 1
fi

# Tu dong tim card mang chinh cua Kali (eth0, ens33, wlan0...)
DEF_DEV=$(ip route get "$REMOTE_IP" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)
if [ -z "$DEF_DEV" ]; then
    DEF_DEV=$(ip route show default | awk '{print $5; exit}')
fi
if [ -z "$DEF_DEV" ]; then
    DEF_DEV="eth0"
fi

echo "[*] Phat hien card mang ket noi Wi-Fi/LAN: $DEF_DEV"
echo "[*] Dang mo cong UDP 4789 cho VXLAN..."
iptables -I INPUT -p udp --dport 4789 -j ACCEPT 2>/dev/null || true

# Don dep cau hinh cu neu co
ip link del vxlan0 2>/dev/null || true
ip link del br0 2>/dev/null || true

if [ "$ROLE" == "host" ]; then
    echo "[*] === KHOI TAO LAPTOP 1: HOST (VICTIM + GATEWAY + DESTINATION) ==="
    for ns in vic gw dst atk h1 h2 amp1 amp2 amp3; do
        ip netns del $ns 2>/dev/null || true
    done

    # 1. Tao switch ao br0 cho mang LAN 10.0.0.0/24
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

    add_host vic 10.0.0.2       # May nan nhan
    add_host gw  10.0.0.1       # Gateway hop phap

    # 2. Khoi tao mang dich 10.0.1.0/24 nam sau Router Gateway
    ip netns add dst            # May chu dich
    ip link add gw-d type veth peer name d-gw
    ip link set gw-d netns gw
    ip link set d-gw netns dst

    ip netns exec gw  ip addr add 10.0.1.254/24 dev gw-d
    ip netns exec gw  ip link set gw-d up
    ip netns exec dst ip addr add 10.0.1.5/24   dev d-gw
    ip netns exec dst ip link set d-gw up
    ip netns exec dst ip link set lo up

    # Cau hinh chuyen tiep tren Gateway
    ip netns exec gw sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    ip netns exec gw sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1
    ip netns exec gw sysctl -w net.ipv4.conf.default.send_redirects=0 >/dev/null 2>&1

    # Thiet lap default gateway
    ip netns exec vic ip route add default via 10.0.0.1
    ip netns exec dst ip route add default via 10.0.1.254

    # Mo lo hong tren Victim (chap nhan ICMP Redirect)
    for k in all vic0; do
        ip netns exec vic sysctl -w net.ipv4.conf.$k.accept_redirects=1 >/dev/null 2>&1
        ip netns exec vic sysctl -w net.ipv4.conf.$k.secure_redirects=0 >/dev/null 2>&1
    done

    # 3. Tao duong ham VXLAN noi br0 sang Laptop 2 qua Wi-Fi
    echo "[*] Dang tao duong ham VXLAN noi toi Laptop 2 ($REMOTE_IP)..."
    ip link add vxlan0 type vxlan id 105 remote "$REMOTE_IP" dstport 4789 dev "$DEF_DEV"
    ip link set vxlan0 master br0
    ip link set vxlan0 up

    echo ""
    echo "=================================================================="
    echo "[+] LAPTOP 1 DA SAN SANG!"
    echo "    - Nạn nhân (vic):        10.0.0.2 (Default GW: 10.0.0.1)"
    echo "    - Gateway hợp pháp (gw): 10.0.0.1"
    echo "    - Máy đích (dst):        10.0.1.5"
    echo "    - Switch br0 da mo ket noi toi Laptop 2 ($REMOTE_IP)!"
    echo ""
    echo "[*] BƯỚC 1 TRÊN LAPTOP 1: Kiểm tra định tuyến ban đầu của Victim:"
    echo "    sudo ip netns exec vic ip route get 10.0.1.5"
    echo "    (Màn hình sẽ báo: 10.0.1.5 via 10.0.0.1 - Đi qua Gateway chuẩn)"
    echo ""
    echo "[*] BƯỚC 2: Chờ Laptop 2 bấm nút tấn công, sau đó kiểm tra lại:"
    echo "    sudo ip netns exec vic ip route get 10.0.1.5"
    echo "    (Màn hình sẽ đổi thành: 10.0.1.5 via 10.0.0.66 ... <redirected>)"
    echo ""
    echo "[*] BƯỚC 3: Thử ping máy đích để thấy gói tin bay sang Laptop 2:"
    echo "    sudo ip netns exec vic ping -c 3 10.0.1.5"
    echo "=================================================================="

elif [ "$ROLE" == "attacker" ]; then
    echo "[*] === KHOI TAO LAPTOP 2: ATTACKER (KẺ TẤN CÔNG ĐỨNG GIỮA MITM) ==="
    for ns in atk vic gw dst; do
        ip netns del $ns 2>/dev/null || true
    done

    # Tao namespace atk va gan VXLAN noi sang Laptop 1
    echo "[*] Dang tao duong ham VXLAN noi toi Laptop 1 ($REMOTE_IP)..."
    ip netns add atk
    ip link add vxlan0 type vxlan id 105 remote "$REMOTE_IP" dstport 4789 dev "$DEF_DEV"
    ip link set vxlan0 netns atk
    ip netns exec atk ip link set vxlan0 name atk0
    ip netns exec atk ip addr add 10.0.0.66/24 dev atk0
    ip netns exec atk ip link set atk0 up
    ip netns exec atk ip link set lo up
    ip netns exec atk sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

    echo ""
    echo "=================================================================="
    echo "[+] LAPTOP 2 DA KET NOI THANH CONG VAO MANG CUA LAPTOP 1!"
    echo "    - Kẻ tấn công (atk):    10.0.0.66"
    echo ""
    echo "[*] BƯỚC 1: Mở terminal theo dõi gói tin bị bẻ lái trên Laptop 2:"
    echo "    sudo ip netns exec atk tcpdump -i atk0 -nn host 10.0.1.5"
    echo ""
    echo "[*] BƯỚC 2: Mở terminal khác trên Laptop 2 và bấm nút tấn công:"
    echo "    sudo ip netns exec atk python3 icmp_redirect.py"
    echo "=================================================================="
fi
