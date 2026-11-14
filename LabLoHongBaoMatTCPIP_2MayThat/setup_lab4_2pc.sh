#!/bin/bash
# setup_lab4_2pc.sh - Trien khai Lab 04 (Smurf Attack) tren 2 Laptop Kali Linux (cung Wi-Fi)
set -e

ROLE=$1
REMOTE_IP=$2

if [ "$ROLE" != "host" ] && [ "$ROLE" != "attacker" ] || [ -z "$REMOTE_IP" ]; then
    echo "=================================================================="
    echo "HUONG DAN SU DUNG CHO 2 LAPTOP (LAB 04 - SMURF ATTACK):"
    echo "------------------------------------------------------------------"
    echo "1. Tren Laptop 1 (May Nan nhan vic & 3 Tram khuech dai amp1-3):"
    echo "   sudo bash setup_lab4_2pc.sh host <IP_KALI_LAPTOP_2>"
    echo "   Vi du: sudo bash setup_lab4_2pc.sh host 192.168.1.20"
    echo ""
    echo "2. Tren Laptop 2 (May Ke tan cong - Attacker):"
    echo "   sudo bash setup_lab4_2pc.sh attacker <IP_KALI_LAPTOP_1>"
    echo "   Vi du: sudo bash setup_lab4_2pc.sh attacker 192.168.1.10"
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
    echo "[*] === KHOI TAO LAPTOP 1: HOST (VICTIM + 3 TRAM KHUECH DAI) ==="
    for ns in vic amp1 amp2 amp3 atk; do
        ip netns del $ns 2>/dev/null || true
    done

    # 1. Tao switch ao br0
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

    add_host vic  10.0.0.200      # May nan nhan (Victim)
    add_host amp1 10.0.0.11       # May khuech dai 1
    add_host amp2 10.0.0.12       # May khuech dai 2
    add_host amp3 10.0.0.13       # May khuech dai 3

    # Mo lo hong broadcast tren cac may amp
    for h in amp1 amp2 amp3; do
        ip netns exec $h sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=0 >/dev/null 2>&1
    done

    # 2. Tao duong ham VXLAN noi br0 sang Laptop 2 qua Wi-Fi
    echo "[*] Dang tao duong ham VXLAN noi toi Laptop 2 ($REMOTE_IP)..."
    ip link add vxlan0 type vxlan id 104 remote "$REMOTE_IP" dstport 4789 dev "$DEF_DEV"
    ip link set vxlan0 master br0
    ip link set vxlan0 up

    echo ""
    echo "=================================================================="
    echo "[+] LAPTOP 1 DA SAN SANG!"
    echo "    - Nạn nhân (vic):        10.0.0.200"
    echo "    - Trạm khuếch đại 1-3:  10.0.0.11, 10.0.0.12, 10.0.0.13"
    echo "    - Switch br0 da mo ket noi toi Laptop 2 ($REMOTE_IP)!"
    echo ""
    echo "[*] BƯỚC TIẾP THEO TRÊN LAPTOP 1 (Mở terminal theo dõi gói tin):"
    echo "    sudo ip netns exec vic tcpdump -i vic0 -nn icmp"
    echo "=================================================================="

elif [ "$ROLE" == "attacker" ]; then
    echo "[*] === KHOI TAO LAPTOP 2: ATTACKER (KẺ TẤN CÔNG THỰC THỤ) ==="
    for ns in atk vic amp1 amp2 amp3; do
        ip netns del $ns 2>/dev/null || true
    done

    # Tao namespace atk va gan VXLAN noi sang Laptop 1
    echo "[*] Dang tao duong ham VXLAN noi toi Laptop 1 ($REMOTE_IP)..."
    ip netns add atk
    ip link add vxlan0 type vxlan id 104 remote "$REMOTE_IP" dstport 4789 dev "$DEF_DEV"
    ip link set vxlan0 netns atk
    ip netns exec atk ip link set vxlan0 name atk0
    ip netns exec atk ip addr add 10.0.0.100/24 dev atk0
    ip netns exec atk ip link set atk0 up
    ip netns exec atk ip link set lo up

    echo ""
    echo "=================================================================="
    echo "[+] LAPTOP 2 DA KET NOI THANH CONG VAO MANG CUA LAPTOP 1!"
    echo "    - Kẻ tấn công (atk):    10.0.0.100"
    echo ""
    echo "[*] BƯỚC 1: Kiểm tra kết nối tới Nạn nhân trên Laptop 1:"
    echo "    sudo ip netns exec atk ping -c 2 10.0.0.200"
    echo ""
    echo "[*] BƯỚC 2: Bấm nút phát động tấn công Smurf từ Laptop 2:"
    echo "    sudo ip netns exec atk python3 smurf_attack.py"
    echo "=================================================================="
fi
