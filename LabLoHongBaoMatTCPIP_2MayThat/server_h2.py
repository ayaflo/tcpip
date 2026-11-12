#!/usr/bin/env python3
# server_h2.py - May chu dich vu chay tren Victim
# Ho tro: Chay ca tren moi truong Ao (Namespace) va 2 May that (Wi-Fi/LAN)
import socket
import sys

# Neu co tham so dong lenh thi dung, mac dinh lang nghe tren moi card mang (0.0.0.0)
HOST = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
    server.bind((HOST, PORT))
    server.listen(5)
    print("==================================================================")
    print(f"[+] MAY CHU VICTIM DANG LANG NGHE TREN: {HOST}:{PORT}")
    print("==================================================================")
    print("[*] San sang nhan ket noi TCP tu cac may khac qua mang Wi-Fi...")
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
