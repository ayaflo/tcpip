#!/bin/bash
# setup_pair_2pc.sh - Trien khai Lab 01, 02, 03, 06 tren 2 Laptop Kali Linux (cung Wi-Fi)
set -e

ROLE=$1
REMOTE_IP=$2

if [ "$ROLE" != "host" ] && [ "$ROLE" != "guest" ] || [ -z "$REMOTE_IP" ]; then
    echo "=================================================================="
    echo "HUONG DAN SU DUNG CHO 2 LAPTOP (LAB 01, 02, 03, 06):"
    echo "------------------------------------------------------------------"
    echo "1. Tren Laptop 1 (May Nan nhan h2 - 10.0.0.2):"
    echo "   sudo bash setup_pair_2pc.sh host <IP_KALI_LAPTOP_2>"
    echo "   Vi du: sudo bash setup_pair_2pc.sh host 192.168.1.20"
    echo ""
    echo "2. Tren Laptop 2 (May Ke tan cong h1 - 10.0.0.1):"
    echo "   sudo bash setup_pair_2pc.sh guest <IP_KALI_LAPTOP_1>"
    echo "   Vi du: sudo bash setup_pair_2pc.sh guest 192.168.1.10"
    echo "=================================================================="
    exit 1
fi

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

ip link del vxlan0 2>/dev/null || true

if [ "$ROLE" == "host" ]; then
    echo "[*] === KHOI TAO LAPTOP 1: MAY NAN NHAN h2 (10.0.0.2) ==="
    ip netns del h2 2>/dev/null || true
    ip netns add h2

    # Tao duong ham VXLAN va chuyen vao namespace h2 voi ten veth2
    ip link add vxlan0 type vxlan id 101 remote "$REMOTE_IP" dstport 4789 dev "$DEF_DEV"
    ip link set vxlan0 netns h2
    ip netns exec h2 ip link set vxlan0 name veth2
    ip netns exec h2 ip addr add 10.0.0.2/24 dev veth2
    ip netns exec h2 ip link set veth2 up
    ip netns exec h2 ip link set lo up

    for k in all veth2; do
        ip netns exec h2 sysctl -w net.ipv4.conf.$k.rp_filter=0 >/dev/null 2>&1 || true
    done

    echo ""
    echo "=================================================================="
    echo "[+] LAPTOP 1 DA SAN SANG (VICTIM h2: 10.0.0.2)!"
    echo "    - Giao diện ảo: veth2"
    echo "    - Đường hầm VXLAN đã nối tới Laptop 2 ($REMOTE_IP)!"
    echo ""
    echo "[*] CÁC LỆNH SẴN SÀNG CHO TỪNG BÀI LAB TRÊN LAPTOP 1:"
    echo "    * Lab 01: sudo ip netns exec h2 python3 server_h2.py"
    echo "    * Lab 02: sudo ip netns exec h2 tcpdump -i veth2 -nn icmp"
    echo "    * Lab 03: sudo ip netns exec h2 sysctl -w net.ipv4.icmp_echo_ignore_all=1"
    echo "              sudo ip netns exec h2 python3 icmp_server.py"
    echo "    * Lab 06: sudo ip netns exec h2 ping -i 0.3 10.0.0.1"
    echo "=================================================================="

elif [ "$ROLE" == "guest" ]; then
    echo "[*] === KHOI TAO LAPTOP 2: MAY ATTACKER h1 (10.0.0.1) ==="
    ip netns del h1 2>/dev/null || true
    ip netns add h1

    # Tao duong ham VXLAN va chuyen vao namespace h1 voi ten veth1
    ip link add vxlan0 type vxlan id 101 remote "$REMOTE_IP" dstport 4789 dev "$DEF_DEV"
    ip link set vxlan0 netns h1
    ip netns exec h1 ip link set vxlan0 name veth1
    ip netns exec h1 ip addr add 10.0.0.1/24 dev veth1
    ip netns exec h1 ip addr add 10.0.0.77/24 dev veth1 2>/dev/null || true
    ip netns exec h1 ip link set veth1 up
    ip netns exec h1 ip link set lo up

    for k in all veth1; do
        ip netns exec h1 sysctl -w net.ipv4.conf.$k.rp_filter=0 >/dev/null 2>&1 || true
    done

    # Chan RST tu kernel
    ip netns exec h1 iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || true

    echo ""
    echo "=================================================================="
    echo "[+] LAPTOP 2 DA KET NOI THANH CONG TOI LAPTOP 1!"
    echo "    - Kẻ tấn công (h1): 10.0.0.1 (Kèm IP phụ giả mạo: 10.0.0.77)"
    echo ""
    echo "[*] KIỂM TRA PING SANG LAPTOP 1 (10.0.0.2) QUA WIFI:"
    ip netns exec h1 ping -c 2 10.0.0.2 || echo "[-] Dang cho Laptop 1 khoi dong..."
    echo ""
    echo "[*] CÁC LỆNH PHÁT ĐỘNG TẤN CÔNG TỪ LAPTOP 2:"
    echo "    * Lab 01: sudo ip netns exec h1 python3 isn_sampler.py"
    echo "              sudo ip netns exec h1 python3 spoof_sniff.py"
    echo "    * Lab 02: sudo ip netns exec h1 python3 ssrr.py"
    echo "    * Lab 03: sudo ip netns exec h1 python3 icmp_client.py"
    echo "    * Lab 06: sudo ip netns exec h1 python3 teardrop_attack.py"
    echo "=================================================================="
fi
