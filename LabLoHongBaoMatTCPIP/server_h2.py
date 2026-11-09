#!/usr/bin/env python3
# server_h2.py - May chu dich vu chay tren Victim (h2)
# Uu diem: Luon luon chay, khong bi tat dot ngot nhu lenh nc thong thuong
import socket
import sys

PORT = 9000
HOST = "10.0.0.2"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[+] MAY CHU VICTIM DANG LANG NGHE TREN {HOST}:{PORT}...")
    print(f"[*] Dang cho ket noi den tu cac client...")
except Exception as e:
    print(f"[-] Khong the mo cong {PORT}: {e}")
    sys.exit(1)

while True:
    try:
        conn, addr = server.accept()
        print(f"\n[!] CO KET NOI MOI! Tu dia chi IP: {addr[0]} (Port: {addr[1]})")
        data = conn.recv(1024)
        if data:
            print(f"[>>>] NOI DUNG NHAN DUOC: {data.decode('utf-8', errors='ignore').strip()}")
        conn.close()
    except KeyboardInterrupt:
        print("\n[*] Dung may chu.")
        break
    except Exception as e:
        pass

