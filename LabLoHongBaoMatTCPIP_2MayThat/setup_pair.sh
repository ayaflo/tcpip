#!/bin/bash
# setup_pair.sh - Tao 2 namespace (h1, h2) noi voi nhau qua cap veth
set -e

# Xoa cac namespace cu neu co de tranh loi trung lap
ip netns del h1 2>/dev/null || true
ip netns del h2 2>/dev/null || true

# 1. Tao 2 "may con" doc lap
ip netns add h1
ip netns add h2

# 2. Tao 1 soi cap mang ao noi giua 2 may (veth1 cam vao h1, veth2 cam vao h2)
ip link add veth1 type veth peer name veth2
ip link set veth1 netns h1
ip link set veth2 netns h2

# 3. Dat dia chi IP cho 2 may
ip netns exec h1 ip addr add 10.0.0.1/24 dev veth1
ip netns exec h2 ip addr add 10.0.0.2/24 dev veth2

# Gan them IP gia mao 10.0.0.77 vao veth1 de h1 nhan duoc goi tra loi tu h2 (on-path)
ip netns exec h1 ip addr add 10.0.0.77/24 dev veth1

# 4. Bat card mang len
ip netns exec h1 ip link set veth1 up
ip netns exec h2 ip link set veth2 up
ip netns exec h1 ip link set lo up
ip netns exec h2 ip link set lo up

# 5. Tat rp_filter (chong loc goi tin gia mao)
for k in all veth1; do ip netns exec h1 sysctl -w net.ipv4.conf.$k.rp_filter=0 >/dev/null 2>&1 || true; done
for k in all veth2; do ip netns exec h2 sysctl -w net.ipv4.conf.$k.rp_filter=0 >/dev/null 2>&1 || true; done

# 6. Chan kernel cua h1 tu gui RST (de Scapy tu quan ly ket noi)
ip netns exec h1 iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || true

echo "[+] Topo 2 may (h1: 10.0.0.1 <---> h2: 10.0.0.2) da san sang!"
echo "[+] Kiem tra ket noi bang lenh ping tu h1 sang h2:"
ip netns exec h1 ping -c 2 10.0.0.2
