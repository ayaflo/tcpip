#!/bin/bash
# setup_dns_2pc.sh - Trien khai Lab 07 (DNSSEC) tren 2 Laptop Kali Linux (cung Wi-Fi)
set -e

ROLE=$1
REMOTE_IP=$2

if [ "$ROLE" != "host" ] && [ "$ROLE" != "client" ] || [ -z "$REMOTE_IP" ]; then
    echo "=================================================================="
    echo "HUONG DAN SU DUNG CHO 2 LAPTOP (LAB 07 - DNSSEC):"
    echo "------------------------------------------------------------------"
    echo "1. Tren Laptop 1 (Chay cac DNS Server: dns-auth, dns-res, rogue):"
    echo "   sudo bash setup_dns_2pc.sh host <IP_KALI_LAPTOP_2>"
    echo "   Vi du: sudo bash setup_dns_2pc.sh host 192.168.1.20"
    echo ""
    echo "2. Tren Laptop 2 (May Khach Client truy van dig):"
    echo "   sudo bash setup_dns_2pc.sh client <IP_KALI_LAPTOP_1>"
    echo "   Vi du: sudo bash setup_dns_2pc.sh client 192.168.1.10"
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
ip link del br0 2>/dev/null || true

if [ "$ROLE" == "host" ]; then
    echo "[*] === KHOI TAO LAPTOP 1: HOST DNS SERVERS ==="
    for ns in dns-auth dns-res rogue client; do
        ip netns del $ns 2>/dev/null || true
    done

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

    add_host dns-auth 10.0.0.2
    add_host dns-res  10.0.0.3
    add_host rogue    10.0.0.66

    # Tao VXLAN noi br0 sang Laptop 2
    ip link add vxlan0 type vxlan id 107 remote "$REMOTE_IP" dstport 4789 dev "$DEF_DEV"
    ip link set vxlan0 master br0
    ip link set vxlan0 up

    echo ""
    echo "=================================================================="
    echo "[+] LAPTOP 1 DA SAN SANG CAC MAY CHU DNS!"
    echo "    - dns-auth: 10.0.0.2 (BIND9 co ky DNSSEC)"
    echo "    - dns-res:  10.0.0.3 (Unbound Resolver kiem thuc)"
    echo "    - rogue:    10.0.0.66 (DNS gia mao)"
    echo "    - Switch br0 da mo ket noi toi Laptop 2 ($REMOTE_IP)!"
    echo ""
    echo "[*] TIEP THEO TREN LAPTOP 1: Chay file setup_dnssec_configs.sh va setup_unbound.sh"
    echo "=================================================================="

elif [ "$ROLE" == "client" ]; then
    echo "[*] === KHOI TAO LAPTOP 2: CLIENT TRUY VAN DIG ==="
    ip netns del client 2>/dev/null || true
    ip netns add client

    ip link add vxlan0 type vxlan id 107 remote "$REMOTE_IP" dstport 4789 dev "$DEF_DEV"
    ip link set vxlan0 netns client
    ip netns exec client ip link set vxlan0 name client0
    ip netns exec client ip addr add 10.0.0.4/24 dev client0
    ip netns exec client ip link set client0 up
    ip netns exec client ip link set lo up

    echo ""
    echo "=================================================================="
    echo "[+] LAPTOP 2 DA SAN SANG (CLIENT: 10.0.0.4)!"
    echo ""
    echo "[*] KIEM TRA PING SANG RESOLVER LAPTOP 1 (10.0.0.3):"
    ip netns exec client ping -c 2 10.0.0.3 || echo "[-] Dang cho Laptop 1 khoi dong..."
    echo ""
    echo "[*] LENH TRUY VAN DIG KIEM THUC DNSSEC TU LAPTOP 2:"
    echo "    sudo ip netns exec client dig @10.0.0.3 www.lab.test +dnssec"
    echo "=================================================================="
fi
