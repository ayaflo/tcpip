# LƯU Ý ĐẶC BIỆT KHI TRIỂN KHAI LAB TRÊN 2 MÁY THẬT
## (Mô hình: 1 Máy Kali trên VMware Laptop Win 11 + 1 Máy Laptop Boot Kali từ Ổ Rời)

> **Mục đích:** Tài liệu này bổ sung và giải quyết triệt để các rào cản kỹ thuật khi kết hợp giữa **máy ảo VMware trên Windows 11** và **máy tính vật lý boot Kali từ ổ cứng ngoài (Live USB/SSD)**.

---

## I. BẢNG PHÂN VAI TỐI ƯU NHẤT CHO 2 MÁY

Để hệ thống hoạt động trơn tru 100%, không bị tường lửa hay cơ chế ảo hóa cản trở, bạn **bắt buộc phải phân vai** như sau:

| Thiết bị | Vai trò gán trong Lab | Lý do kỹ thuật |
|---|---|---|
| **Laptop Boot Kali từ Ổ Rời (Bare-Metal)** | **MÁY 2 (Victim / Server)** | - Quản lý card Wi-Fi thật trực tiếp, **bật Wi-Fi Hotspot** để phát mạng cho máy kia bắt vào (tránh bị Router quán cafe/trường học chặn gói tin qua AP Isolation).<br>- Làm máy chủ lắng nghe dịch vụ: `server_h2.py` (cổng 9000), `icmp_server.py`, DNS BIND9 + Unbound (cổng 53), hứng mảnh Teardrop (Lab 06). |
| **Laptop Win 11 (Kali trên VMware)** | **MÁY 1 (Attacker / Client)** | - Bắt vào mạng Wi-Fi Hotspot của Laptop 2.<br>- Cấu hình mạng VMware ở chế độ **Bridged**.<br>- Chạy các kịch bản tấn công/truy vấn: `isn_sampler.py`, `spoof_sniff.py`, `icmp_client.py`, `teardrop_attack.py`, `dig` DNSSEC. |

---

## II. 5 "TỬ HUYỆT" KỸ THUẬT VÀ CÁCH XỬ LÝ TRIỆT ĐỂ

### 1. Tử huyệt 1: Card mạng VMware (BẮT BUỘC CHỌN BRIDGED, CẤM DÙNG NAT)
- **Hiện tượng nếu để NAT (Mặc định):**
  - Kali trong VMware nhận dải IP ảo riêng (`192.168.174.x`).
  - Máy ngoài (Laptop boot ổ rời) **hoàn toàn KHÔNG THỂ ping hay gửi bất kỳ gói tin nào** vào Kali trong VMware.
- **Cách chỉnh trên Windows 11:**
  1. Tắt máy ảo Kali trên VMware.
  2. Chuột phải vào máy ảo Kali $\rightarrow$ Chọn `Settings` $\rightarrow$ Chọn phần cứng `Network Adapter`.
  3. Tích chọn **Bridged: Connected directly to the physical network**.
  4. Mở menu trên thanh công cụ VMware: `Edit` $\rightarrow$ `Virtual Network Editor...` $\rightarrow$ Bấm nút **Change Settings** (yêu cầu quyền Administrator).
  5. Chọn dòng **`VMnet0 (Bridged)`**:
     - Tại ô `Bridged to:`, **chọn đích danh tên Card Wi-Fi thật của Laptop Win 11** (Ví dụ: *Intel(R) Wi-Fi 6 AX201...* hoặc *Realtek 8821CE...*).
     - **TUYỆT ĐỐI KHÔNG ĐỂ `Automatic`** (vì VMware sẽ nhận nhầm vào card mạng ảo, card Bluetooth hoặc card LAN).
  6. Bấm `Apply` $\rightarrow$ `OK`. Khởi động lại máy ảo Kali.

---

### 2. Tử huyệt 2: Tên Card Mạng (Interface) bị lệch giữa 2 máy!
Trong các file hướng dẫn chung thường viết mặc định là `wlan0`. Nhưng trên thực tế:
- **Trên Laptop Boot Ổ Rời:** Linux nhận trực tiếp chip Wi-Fi thật nên tên card là **`wlan0`** (hoặc `wlp2s0`, `wlp3s0`).
- **Trên Kali trong VMware:** Dù laptop Win 11 bắt Wi-Fi, nhưng VMware biến nó thành một card mạng dây ảo trong Linux, có tên là **`eth0`** (hoặc `ens33`). **TRONG VMWARE KHÔNG HỀ CÓ `wlan0`!**
- **Quy tắc vàng:**
  - Gõ lệnh `ip -4 a` trên cả 2 máy để xem chính xác card nào đang có địa chỉ IP.
  - Trên máy VMware: Thay toàn bộ chữ `wlan0` trong các câu lệnh thành `eth0` (hoặc `ens33`).

---

### 3. Tử huyệt 3: Tạo đường truyền Wi-Fi trực tiếp (Wi-Fi Hotspot)
Không nên dùng Wi-Fi công cộng (quán cà phê, thư viện) vì các router này thường bật tính năng **Client Isolation** (cấm 2 máy cùng bắt Wi-Fi gửi gói tin cho nhau).
- **Cách bật Hotspot trên Laptop 2 (Boot ổ rời):**
  1. Trong Kali Linux, vào `Settings` $\rightarrow$ `Wi-Fi`.
  2. Bấm vào menu 3 chấm ở góc trên bên phải $\rightarrow$ Chọn **Turn On Wi-Fi Hotspot...**
  3. Đặt tên mạng (SSID) và Mật khẩu (Network Key). Bấm `Turn On`.
  4. Kiểm tra IP của máy 2: `ip -4 addr show wlan0` (thường sẽ là `192.168.12.1` hoặc `10.42.0.1`).
- **Trên Laptop 1 (Win 11):**
  1. Bắt vào Wi-Fi Hotspot do Laptop 2 phát ra.
  2. Vào máy ảo Kali VMware, kiểm tra: `ip -4 addr show eth0`.
  3. Lúc này máy ảo Kali sẽ tự động nhận IP cùng dải với Laptop 2 (ví dụ: `192.168.12.15`).

---

### 4. Tử huyệt 4: Tắt dịch vụ chiếm cổng 53 trước khi làm Lab 07 (DNSSEC)
- **Vấn đề:** Trên Kali Linux, dịch vụ hệ thống `systemd-resolved` thường chiếm sẵn cổng `53`. Khi chạy BIND9/Unbound sẽ bị báo lỗi `Address already in use`.
- **Cách xử lý trên Máy 2 (DNS Server):**
  ```bash
  sudo systemctl stop systemd-resolved
  ```

---

### 5. Tử huyệt 5: Tường lửa Windows 11 Host
- **Vấn đề:** Tường lửa của Windows 11 đôi khi coi mạng Hotspot là mạng công cộng (Public Network) và tự động chặn các gói tin ARP hoặc gói tin phân mảnh truyền vào VMware.
- **Cách xử lý trên Windows 11:** Tạm thời tắt Windows Defender Firewall trong lúc làm thực hành:
  - Mở `Windows Security` $\rightarrow$ `Firewall & network protection` $\rightarrow$ Tắt tạm thời ở mục `Private network` và `Public network`.

---

## III. QUY TRÌNH KIỂM TRA THÔNG MẠNG (HEALTH CHECK BẮT BUỘC)

Trước khi thực hiện bất kỳ bài lab nào, hãy chạy 2 bước sau để đảm bảo 2 máy đã thông nhau 100%:

1. **Bước 1: Kiểm tra IP của 2 máy**
   - Máy 2 (Boot ổ rời): `ip -4 a show wlan0` $\rightarrow$ Giả sử ra `192.168.12.1`
   - Máy 1 (VMware Kali): `ip -4 a show eth0` $\rightarrow$ Giả sử ra `192.168.12.15`

2. **Bước 2: Ping kiểm tra 2 chiều**
   - Từ Máy 1 (VMware): `ping -c 3 192.168.12.1`
   - Từ Máy 2 (Boot ổ rời): `ping -c 3 192.168.12.15`
   - **Kết quả:** Cả 2 máy đều phản hồi `0% packet loss` thì hệ thống đã hoàn toàn sẵn sàng!

---

## IV. BẢNG TỔNG HỢP CÂU LỆNH CHUẨN XÁC THEO CARD MẠNG

| Bài Lab | Trên Máy 2 (Victim / Server - Card `wlan0`) | Trên Máy 1 (Attacker / Client - Card `eth0`) |
|---|---|---|
| **Lab 01 (ISN)** | `python3 server_h2.py` | `sudo python3 isn_sampler.py <IP_M2>`<br>`sudo python3 spoof_sniff.py <IP_M2> <IP_SPOOF> eth0` |
| **Lab 02 (SSRR)** | `sudo sysctl -w net.ipv4.conf.all.accept_source_route=1 net.ipv4.conf.wlan0.accept_source_route=1`<br>`sudo tcpdump -i wlan0 -nn -v icmp` | `sudo python3 ssrr.py <IP_M2> <IP_M1> eth0` |
| **Lab 03 (Tunnel)** | `sudo iptables -F`<br>`sudo iptables -A INPUT -p tcp --dport 9999 -j DROP`<br>`sudo python3 icmp_server.py wlan0` | `sudo python3 icmp_client.py <IP_M2> eth0` |
| **Lab 04 (Smurf)** | *(Chạy mô phỏng trên 1 máy bằng Network Namespace)*<br>`sudo bash setup_lan.sh` $\rightarrow$ chạy test $\rightarrow$ `sudo bash clean_lan.sh` | |
| **Lab 05 (Redirect)**| *(Chạy mô phỏng trên 1 máy bằng Network Namespace)*<br>`sudo bash setup_redirect.sh` $\rightarrow$ chạy test $\rightarrow$ `sudo bash clean_redirect.sh` | |
| **Lab 06 (Teardrop)**| `netstat -s \| grep -i -E "reassembl\|fragments"`<br>`sudo tcpdump -i wlan0 -nn -v 'ip[6:2] & 0x3fff != 0'` | `sudo python3 teardrop_attack.py <IP_M2> eth0`<br>`ping -c 3 <IP_M2>` |
| **Lab 07 (DNSSEC)**| `sudo systemctl stop systemd-resolved`<br>`sudo bash setup_dnssec_configs_real.sh <IP_M2>`<br>`named -c /etc/bind/named-auth.conf -g &`<br>`bash setup_unbound_real.sh <IP_M2>`<br>`unbound -c /etc/unbound/unbound.conf -d &` | `dig @<IP_M2> www.lab.test +dnssec` |

