# HƯỚNG DẪN TRIỂN KHAI TOÀN DIỆN TRÊN 2 MÁY THẬT (KALI LINUX — CÙNG MẠNG WI-FI)

> [!IMPORTANT]
> **ĐẶC BIỆT KHI DÙNG 1 MÁY VMWARE (WIN 11) + 1 MÁY BOOT KALI TỪ Ổ RỜI:**
> Hãy đọc ngay tài liệu bổ sung [LUU_Y_TRIEN_KHAI_VMWARE_VS_MAY_THAT.md](LUU_Y_TRIEN_KHAI_VMWARE_VS_MAY_THAT.md) để:
> 1. Chuyển card mạng VMware sang **Bridged** (cấm dùng NAT).
> 2. Đổi tên card mạng từ `wlan0` sang `eth0` (hoặc `ens33`) trên máy VMware.
> 3. Bật Wi-Fi Hotspot từ máy Boot ổ rời làm Server.
> 4. Tắt `systemd-resolved` trước khi chạy Lab 07.

Tài liệu này hướng dẫn chi tiết cách tổ chức, chuẩn bị mạng và thực thi các bài thực hành trong chuyên đề **An toàn Giao thức TCP/IP** khi triển khai trên **2 máy tính vật lý thật**, cả hai đều cài đặt **Kali Linux** và kết nối **chung một mạng Wi-Fi**.

---

## I. BẢNG PHÂN LOẠI KHẢ NĂNG TRIỂN KHAI TRÊN 2 MÁY THẬT

Dựa trên nguyên lý hoạt động của các tầng giao thức mạng và giới hạn vật lý của sóng vô tuyến Wi-Fi (802.11), các bài lab được phân loại như sau:

| Bài Lab | Tên bài thực hành | Khả năng chạy trên 2 máy thật Wi-Fi | Lý do kỹ thuật & Giải pháp triển khai |
| :---: | :--- | :---: | :--- |
| **Lab 01** | **TCP Sequence Number Prediction & Spoofing** | **RẤT TỐT (100%)** | • Phần 1 (Lấy mẫu ISN): Máy 1 gửi SYN qua Wi-Fi tới cổng 9000 của Máy 2, trích xuất ISN và phân tích ngẫu nhiên RFC 6528.<br/>• Phần 2 (Giả mạo IP): Script được nâng cấp tự động phản hồi ARP cho IP giả mạo, cho phép Máy 2 gửi SYN/ACK về Máy 1 qua Wi-Fi trơn tru. |
| **Lab 02** | **IP Source Routing (SSRR)** | **TỐT (Cần lưu ý AP)** | Hai máy cùng subnet Wi-Fi trao đổi trực tiếp ở Layer 2 qua AP Bridge. Máy 2 bật `accept_source_route=1`. Máy 1 gửi gói SSRR ép phản hồi về máy mình.<br/>*(Mẹo: Nếu Router Wi-Fi chặn IP options, Máy 2 bật Hotspot cho Máy 1 kết nối trực tiếp).* |
| **Lab 03** | **ICMP Tunneling (Kênh ngầm dữ liệu)** | **HOÀN HẢO (100%)** | **Bài lab ấn tượng và thực tế nhất trên 2 laptop!** Máy 2 chặn TCP bằng iptables, chạy `icmp_server.py`. Máy 1 chạy `icmp_client.py` tuồn dữ liệu mật qua ping Wi-Fi. Máy 2 thu thập và tái tạo dữ liệu mật 71 bytes tức thì! |
| **Lab 04** | **Smurf Attack (Broadcast Amplification DoS)** | **KHÓ TRIỂN KHAI (GIỮ NGUYÊN MÔ PHỎNG)** | • **Lý do:** Smurf cần một đội quân nhiều máy tính (Amplifiers) để khuếch đại lưu lượng dội về nạn nhân. Nếu chỉ có 2 máy thật thì **không có thực thể khuếch đại**.<br/>• Ngoài ra, Router Wi-Fi theo chuẩn RFC 2644 đều chặn directed broadcast ping (`.255`) để bảo vệ sóng vô tuyến.<br/>$\rightarrow$ **Giữ nguyên mô hình Network Namespace (5 máy qua Bridge ảo `br0`) để thể hiện đúng hệ số khuếch đại $\times 3$ lần.** |
| **Lab 05** | **ICMP Redirect Attack (Route Hijacking)** | **KHÓ TRIỂN KHAI (GIỮ NGUYÊN MÔ PHỎNG)** | • **Lý do:** Đòi hỏi 4 node mạng độc lập (Gateway hợp pháp, Nạn nhân, Attacker, Mạng đích subnet khác).<br/>• Trên Wi-Fi thật, Router Wi-Fi thật là gateway duy nhất; kẻ tấn công không thể tự xưng là router thật một cách an toàn mà không làm mất kết nối mạng của cả phòng, đồng thời Kernel Linux chặn gói redirect giả mạo router ngoài subnet.<br/>$\rightarrow$ **Giữ nguyên mô hình Network Namespace 4 node chuẩn hóa.** |
| **Lab 06** | **Teardrop Attack (IP Fragmentation Overlap)** | **HOÀN HẢO (100%)** | Máy 1 gửi 2 mảnh IP chồng lấn 16 bytes qua Wi-Fi tới IP của Máy 2. Kernel của Máy 2 nhận mảnh, xử lý tái hợp, phát hiện lỗi đè và tăng bộ đếm `ReasmFails` lên 1 trên card `wlan0`, máy vẫn sống sót bình thường! |
| **Lab 07** | **DNSSEC (Xác thực tên miền an toàn)** | **RẤT TỐT (Mô hình Client - Server)** | Máy 2 đóng vai Máy chủ DNS nội bộ (chạy BIND9 có ký DNSSEC và Resolver Unbound). Máy 1 đóng vai Client kết nối Wi-Fi, dùng `dig` truy vấn nhận cờ `ad` và chữ ký `RRSIG`. Khi chuyển sang máy giả mạo `rogue` $\rightarrow$ nhận lỗi `SERVFAIL`! |

---

## II. THIẾT LẬP MẠNG CHO 2 MÁY THẬT

### 1. Phân vai 2 máy tính
* **MÁY 1 (Attacker / Client):**
  * Đóng vai: Kẻ tấn công hoặc Máy khách gửi truy vấn.
  * Card mạng: `wlan0`.
  * Giả sử có IP Wi-Fi: `IP_MAY_1` (ví dụ `192.168.1.100`).
* **MÁY 2 (Victim / Server):**
  * Đóng vai: Nạn nhân hoặc Máy chủ dịch vụ (TCP Server, ICMP Receiver, DNS Server).
  * Card mạng: `wlan0`.
  * Giả sử có IP Wi-Fi: `IP_MAY_2` (ví dụ `192.168.1.105`).

---

### 2. Cách xem địa chỉ IP Wi-Fi trên từng máy
Mở terminal trên từng máy và gõ:
```bash
ip -4 addr show wlan0 | grep inet
```
*Kết quả sẽ có dạng:* `inet 192.168.1.105/24 brd 192.168.1.255 scope global dynamic wlan0`. Địa chỉ sau chữ `inet` chính là IP Wi-Fi của máy.

---

### 3. Mẹo quan trọng nhất: "Chế độ Wi-Fi Hotspot trực tiếp giữa 2 máy"
> [!TIP]
> Trong một số mạng Wi-Fi công cộng (quán cà phê, trường học, ký túc xá), Router Wi-Fi thường bật tính năng **AP Isolation / Client Isolation** (cấm 2 máy tính cùng bắt Wi-Fi nhìn thấy nhau) hoặc bật tường lửa chặn gói tin đặc biệt (IP Options, ICMP lạ).
> 
> **Giải pháp tối ưu 100%:**
> 1. Trên **Máy 2 (Server)**: Bật tính năng **Wi-Fi Hotspot** (Chia sẻ mạng Wi-Fi từ Kali Linux: Settings $\rightarrow$ Wi-Fi $\rightarrow$ Turn On Wi-Fi Hotspot).
> 2. Trên **Máy 1 (Client)**: Bắt vào mạng Wi-Fi Hotspot do Máy 2 phát ra.
> 
> Khi đó: Hai máy kết nối trực tiếp với nhau, không có bất kỳ router trung gian nào can thiệp, toàn bộ các bài Lab 01, 02, 03, 06, 07 sẽ chạy mượt mà 100%!

---

## III. HƯỚNG DẪN THỰC THI CHI TIẾT TỪNG BÀI

### 1. LAB 01 — TCP SEQUENCE NUMBER PREDICTION & SPOOFING
* **Trên Máy 2 (Victim):**
  ```bash
  # Chạy máy chủ TCP lắng nghe trên cổng 9000
  python3 server_h2.py
  ```
* **Trên Máy 1 (Attacker):**
  ```bash
  # Phần 1: Lấy mẫu 30 số ISN từ Máy 2 qua Wi-Fi
  sudo python3 isn_sampler.py <IP_MAY_2>
  
  # Phần 2: Tấn công giả mạo IP nguồn
  sudo python3 spoof_sniff.py <IP_MAY_2>
  ```

---

### 2. LAB 02 — IP SOURCE ROUTING (SSRR)
* **Trên Máy 2 (Victim):**
  ```bash
  # Bật tính năng chấp nhận Source Route trên card wlan0
  sudo sysctl -w net.ipv4.conf.all.accept_source_route=1 net.ipv4.conf.wlan0.accept_source_route=1
  # Bật tcpdump theo dõi
  sudo tcpdump -i wlan0 -nn -v icmp
  ```
* **Trên Máy 1 (Attacker):**
  ```bash
  # Gửi gói tin SSRR qua Wi-Fi ép Máy 2 phản hồi về Máy 1
  sudo python3 ssrr.py <IP_MAY_2> <IP_MAY_1> wlan0
  ```
* **Kiểm chứng phòng thủ trên Máy 2:**
  ```bash
  sudo sysctl -w net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.wlan0.accept_source_route=0
  ```

---

### 3. LAB 03 — ICMP TUNNELING (KÊNH TRUYỀN NGẦM)
* **Trên Máy 2 (Server):**
  ```bash
  # Chặn TCP cổng 9999
  sudo iptables -F
  sudo iptables -A INPUT -p tcp --dport 9999 -j DROP
  
  # Bật server ICMP lắng nghe kênh ngầm
  sudo python3 icmp_server.py
  ```
* **Trên Máy 1 (Client):**
  ```bash
  # Kiểm tra TCP bị chặn nhưng ICMP thông suốt
  nc -z -v -w 2 <IP_MAY_2> 9999
  ping -c 2 <IP_MAY_2>
  
  # Bắn dữ liệu mật qua kênh ping Wi-Fi
  sudo python3 icmp_client.py <IP_MAY_2>
  ```
* **Kết quả:** Máy 2 nhận và tái hợp dữ liệu mật 71 bytes tức thì!

---

### 4. LAB 04 — SMURF ATTACK (BROADCAST AMPLIFICATION DoS)
* **Khuyến nghị:** Thực hiện trên **Máy 1** (hoặc Máy 2) sử dụng mô hình Network Namespace với Switch ảo `br0` và 5 máy ảo.
* **Lý do:** Mô phỏng chân thực hệ số khuếch đại $\times 3$ lần mà không bị router Wi-Fi chặn gói broadcast.
* **Lệnh chạy:**
  ```bash
  sudo bash setup_lan.sh
  # Terminal 1:
  sudo ip netns exec vic tcpdump -i vic0 -nn icmp
  # Terminal 2:
  sudo ip netns exec atk python3 smurf_attack.py
  # Dọn dẹp:
  sudo bash clean_lan.sh
  ```

---

### 5. LAB 05 — ICMP REDIRECT ATTACK (ROUTE HIJACKING)
* **Khuyến nghị:** Thực hiện trên **Máy 1** (hoặc Máy 2) sử dụng mô hình Network Namespace 4 node (`gw`, `vic`, `atk`, `dst`).
* **Lý do:** Kiểm soát toàn diện bảng định tuyến của Gateway hợp pháp và mạng đích, vượt qua các chốt chặn `NUD_VALID` của Kernel Linux an toàn.
* **Lệnh chạy:**
  ```bash
  sudo bash setup_redirect.sh
  # Terminal 1 (atk bắt gói tin):
  sudo ip netns exec atk tcpdump -i atk0 -nn host 10.0.1.5
  # Terminal 2 (vic kiểm tra định tuyến):
  sudo ip netns exec vic ip route get 10.0.1.5
  # Terminal 3 (atk tấn công):
  sudo ip netns exec atk python3 icmp_redirect.py
  # Terminal 2 (vic kiểm tra lại & ping):
  sudo ip netns exec vic ip route get 10.0.1.5
  sudo ip netns exec vic ping -c 2 10.0.1.5
  # Dọn dẹp:
  sudo bash clean_redirect.sh
  ```

---

### 6. LAB 06 — TEARDROP ATTACK (IP FRAGMENTATION OVERLAP)
* **Trên Máy 2 (Victim):**
  ```bash
  # Kiểm tra bộ đếm trước tấn công (ReasmFails = 0)
  netstat -s | grep -i -E "reassembl|fragments"
  
  # Bật tcpdump bắt các mảnh phân mảnh trên card wlan0
  sudo tcpdump -i wlan0 -nn -v 'ip[6:2] & 0x3fff != 0'
  ```
* **Trên Máy 1 (Attacker):**
  ```bash
  # Gửi các mảnh IP chồng lấn 16 bytes qua Wi-Fi tới Máy 2
  sudo python3 teardrop_attack.py <IP_MAY_2> wlan0
  
  # Đo nhịp tim ping xem Máy 2 có sống sót không
  ping -c 3 <IP_MAY_2>
  ```
* **Kiểm tra trên Máy 2:**
  ```bash
  # Bộ đếm ReasmReqds tăng 2, ReasmFails tăng 1 -> Kernel xử lý an toàn!
  netstat -s | grep -i -E "reassembl|fragments"
  ```

---

### 7. LAB 07 — DNSSEC (XÁC THỰC TÊN MIỀN AN TOÀN)
* **Trên Máy 2 (DNS Server):**
  ```bash
  # Khởi tạo file cấu hình DNSSEC cho máy thật
  sudo bash setup_dnssec_configs_real.sh <IP_MAY_2>
  
  # Chạy BIND9 có ký DNSSEC
  sudo su
  named -c /etc/bind/named-auth.conf -g &
  
  # Trích xuất Trust Anchor và tạo cấu hình Unbound
  bash setup_unbound_real.sh <IP_MAY_2>
  
  # Chạy Unbound Resolver
  unbound -c /etc/unbound/unbound.conf -d &
  ```
* **Trên Máy 1 (Client):**
  ```bash
  # Truy vấn DNSSEC qua sóng Wi-Fi tới Máy 2
  dig @<IP_MAY_2> www.lab.test +dnssec
  ```
  *Quan sát:* `status: NOERROR`, cờ `ad` (Authenticated Data) xuất hiện, nhận IP `10.0.0.80` kèm `RRSIG`!
* **Kiểm chứng tấn công giả mạo (Trên Máy 2):**
  ```bash
  # Khởi động Rogue DNS không ký
  named -c /etc/bind/named-rogue.conf -g &
  # Bẻ hướng Unbound sang Rogue
  sed -i "s/stub-addr: .*/stub-addr: 127.0.0.1@5353/" /etc/unbound/unbound.conf
  pkill -9 -f unbound
  unbound -c /etc/unbound/unbound.conf -d &
  ```
* **Truy vấn lại từ Máy 1:**
  ```bash
  # Nhận ngay lỗi SERVFAIL, dữ liệu giả mạo bị chặn đứng!
  dig @<IP_MAY_2> www.lab.test +dnssec
  
  # Tắt kiểm tra bằng cờ +cd -> Nhận IP giả 6.6.6.6!
  dig @<IP_MAY_2> www.lab.test +cd +short
  ```
