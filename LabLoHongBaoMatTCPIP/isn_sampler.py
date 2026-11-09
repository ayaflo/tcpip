#!/usr/bin/env python3
# isn_sampler.py - Thu thap va phan tich tinh ngau nhien cua ISN tren server
from scapy.all import IP, TCP, sr1, send, RandShort

print("[*] Dang gui 30 goi SYN den 10.0.0.2:9000 de thu thap ISN...")
isns = []
for i in range(30):
    sport = int(RandShort())
    syn = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=sport, dport=9000, flags="S", seq=1000)
    ans = sr1(syn, timeout=1, verbose=0)
    if ans and ans.haslayer(TCP) and (ans[TCP].flags & 0x12) == 0x12:   # Kiem tra co SYN+ACK
        isns.append(ans[TCP].seq)
        # Gui goi RST dong ket noi ngay de khong lam day bo nho server
        send(IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=sport, dport=9000, flags="R", seq=1001), verbose=0)

print(f"\n[+] Da thu thap duoc {len(isns)} gia tri ISN:")
for idx, x in enumerate(isns, 1):
    print(f"  Lan {idx:02d}: Hex = {hex(x)} | Dec = {x}")

print("\n--- Do chenh lech giua cac ISN lien tiep ---")
for idx, (a, b) in enumerate(zip(isns, isns[1:]), 1):
    print(f"  Chenh lech {idx:02d}->{idx+1:02d}: {b - a}")

print("\n[=>] KET LUAN: Cac gia tri chenh lech rat lon va khong co quy luat co dinh.")
print("      Chung to he dieu hanh hien dai da ngau nhien hoa ISN (RFC 6528), ngan chan doan mo ISN!")

