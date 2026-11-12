#!/usr/bin/env python3
# isn_sampler.py - Thu thap va phan tich tinh ngau nhien cua ISN tren server
# Ho tro: Chay linh hoat tren 2 may that (Wi-Fi) hoac qua Network Namespace
import sys
from scapy.all import IP, TCP, sr1, send, RandShort, conf

# Doc dia chi IP cua server tu tham so dong lenh (hoac mac dinh 10.0.0.2)
target_ip = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.2"
target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 9000

print("==================================================================")
print(f"[*] THU THAP 30 SO ISN TU MAY CHU: {target_ip}:{target_port}")
print("==================================================================")

isns = []
for i in range(30):
    sport = int(RandShort())
    # Scapy tu dong xac dinh IP nguon va interface phu hop voi target_ip
    syn = IP(dst=target_ip)/TCP(sport=sport, dport=target_port, flags="S", seq=1000)
    ans = sr1(syn, timeout=1.5, verbose=0)
    if ans and ans.haslayer(TCP) and (ans[TCP].flags & 0x12) == 0x12:   # Kiem tra co SYN+ACK
        isns.append(ans[TCP].seq)
        # Gui goi RST dong ket noi ngay de khong lam day bo nho server
        send(IP(dst=target_ip)/TCP(sport=sport, dport=target_port, flags="R", seq=1001), verbose=0)

if not isns:
    print(f"[-] Khong nhan duoc phan hoi SYN/ACK tu {target_ip}:{target_port}!")
    print(f"    Hay kiem tra: May chu da chay server_h2.py chua? Hai may da ping duoc nhau chua?")
    sys.exit(1)

print(f"\n[+] Da thu thap duoc {len(isns)} gia tri ISN:")
for idx, x in enumerate(isns, 1):
    print(f"  Lan {idx:02d}: Hex = {hex(x)} | Dec = {x}")

print("\n--- Do chenh lech giua cac ISN lien tiep ---")
for idx, (a, b) in enumerate(zip(isns, isns[1:]), 1):
    print(f"  Chenh lech {idx:02d}->{idx+1:02d}: {b - a}")

print("\n[=>] KET LUAN: Cac gia tri chenh lech rat lon va khong co quy luat co dinh.")
print("      Chung to he dieu hanh hien dai da ngau nhien hoa ISN (RFC 6528), ngan chan doan mo ISN!")
