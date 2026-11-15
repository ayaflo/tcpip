# LƯU Ý ĐẶC BIỆT KHI TRIỂN KHAI LAB TRÊN 2 MÁY THẬT (VMWARE BRIDGED TRÊN CÙNG MẠNG WI-FI)

> **Mục đích:** Tài liệu này giải quyết triệt để các rào cản kỹ thuật khi triển khai các bài thực hành trên **2 máy laptop vật lý khác nhau, cùng chạy Kali Linux trên VMware Workstation ở chế độ Bridged qua mạng Wi-Fi**.

---

## I. MÔ HÌNH TRIỂN KHAI & PHÂN VAI GIỮA 2 LAPTOP

Hệ thống gồm 2 laptop vật lý chạy Windows 10/11, cài đặt **VMware Workstation** và chạy máy ảo **Kali Linux**. Cả hai laptop cùng kết nối vào một mạng Wi-Fi (hoặc kết nối qua Hotspot):

| Thiết bị | Vai trò gán trong Lab | Nhiệm vụ kỹ thuật |
|---|---|---|
| **Laptop 1 (Kali trên VMware Bridged)** | **MÁY 1 (Attacker / Client)** | - Đóng vai Kẻ tấn công hoặc Client kiểm thử.<br>- Thực hiện các lệnh tấn công: `isn_sampler.py`, `spoof_sniff.py`, `icmp_client.py`, `teardrop_attack.py`, `dig` DNSSEC.<br>- Với Lab 04 & Lab 05: Đóng vai `attacker` tham gia mạng qua VXLAN (`setup_lab4_2pc.sh attacker <IP_M2>` / `setup_lab5_2pc.sh attacker <IP_M2>`). |
| **Laptop 2 (Kali trên VMware Bridged)** | **MÁY 2 (Victim / Server / Host)** | - Đóng vai Nạn nhân hoặc Máy chủ dịch vụ mạng.<br>- Mở dịch vụ: `server_h2.py` (cổng 9000), `icmp_server.py`, DNS BIND9 + Unbound (cổng 53), hứng mảnh Teardrop (Lab 06).<br>- Với Lab 04 & Lab 05: Đóng vai `host` dựng Nạn nhân + Trạm khuếch đại / Gateway ảo (`setup_lab4_2pc.sh host <IP_M1>` / `setup_lab5_2pc.sh host <IP_M1>`). |

*(Ghi chú: Nếu một trong hai máy là laptop boot Kali trực tiếp từ USB/ổ cứng ngoài - bare-metal, các bước thực hiện hoàn toàn tương tự, chỉ khác là máy bare-metal có thể mang tên card là `wlan0`).*

---

## II. 5 NGUYÊN TẮC VÀ LƯU Ý SỐNG CÒN KHI DÙNG VMWARE BRIDGED

### 1. Tại sao trong Kali VMware KHÔNG CÓ card `wlan0` mà là `eth0`?
- **Nguyên lý ảo hóa mạng:** Máy ảo VMware không bao giờ nhìn thấy trực tiếp phần cứng chip Wi-Fi (802.11) của máy tính vật lý. Thay vào đó, VMware Bridge Protocol ở tầng Windows Host sẽ bắc cầu dữ liệu và giả lập cho Kali Linux một card mạng Ethernet có dây ảo (802.3).
- **Hệ quả:** 
  - Trong Kali Linux của VMware, tên card mạng kết nối luôn là **`eth0`** (hoặc `ens33` nếu bật Predictable Interface Names). **Hoàn toàn KHÔNG TỒN TẠI `wlan0`!**
  - Nếu gõ `ip a show wlan0` hoặc `tcpdump -i wlan0`, hệ thống sẽ báo lỗi ngay lập tức: `Device "wlan0" does not exist.`
- **Quy tắc:**
  - Trên cả Máy 1 và Máy 2 (VMware): Mọi câu lệnh `tcpdump`, `sysctl`, và script Python đều truyền tên card là **`eth0`** (hoặc tên card hiển thị từ lệnh `ip -br a`).

---

### 2. Câu lệnh xem IP máy chuẩn xác & nhanh nhất trên Kali VMware
Để tránh nhầm lẫn tên card mạng, hãy sử dụng các lệnh chuẩn sau:
* **Lệnh nhanh nhất (Khuyên dùng):**
  ```bash
  hostname -I
  ```
  *In ra ngay địa chỉ IP của máy (Ví dụ: `192.168.1.100`), cực kỳ ngắn gọn, không lo lỗi cú pháp.*
* **Lệnh xem bảng chi tiết các card mạng:**
  ```bash
  ip -br addr
  ```
  *In ra danh sách dạng bảng rất sạch sẽ:*
  ```text
  lo               UNKNOWN        127.0.0.1/8 ::1/128 
  eth0             UP             192.168.1.100/24 fe80::...
  ```
* **Lệnh xem chi tiết riêng card `eth0`:**
  ```bash
  ip -4 addr show eth0
  ```

---

### 3. Cấu hình VMware Bridged chuẩn xác trên Windows (Tránh mất mạng)
Để máy ảo Kali nhận IP trực tiếp từ Wi-Fi và nhìn thấy máy ảo của laptop kia, **bắt buộc cấu hình chế độ Bridged**:
1. Tắt máy ảo Kali trên cả 2 laptop.
2. Chuột phải vào máy ảo Kali $\rightarrow$ Chọn `Settings` $\rightarrow$ Chọn phần cứng `Network Adapter`.
3. Tích chọn **Bridged: Connected directly to the physical network**.
4. Mở menu trên thanh công cụ VMware Workstation: `Edit` $\rightarrow$ `Virtual Network Editor...` $\rightarrow$ Bấm nút **Change Settings** (yêu cầu quyền Administrator).
5. Chọn dòng **`VMnet0 (Bridged)`**:
   - Tại ô `Bridged to:`, **chọn đích danh tên Card Wi-Fi thật của Laptop** (Ví dụ: *Intel(R) Wi-Fi 6 AX201 160MHz* hoặc *Realtek RTL8821CE 802.11ac PCIe Adapter*).
   - **TUYỆT ĐỐI KHÔNG ĐỂ `Automatic`** (vì VMware có thể tự động gán nhầm sang card mạng ảo, card LAN không cắm dây, hoặc card Bluetooth).
6. Bấm `Apply` $\rightarrow$ `OK`. Khởi động lại máy ảo Kali trên cả 2 laptop.

---

### 4. Giải quyết triệt để rào cản Wi-Fi AP Isolation (Client Isolation)
Trong các mạng Wi-Fi công cộng (trường đại học, quán cà phê, ký túc xá), Router Wi-Fi thường bật tính năng **AP Isolation** (ngăn các thiết bị cùng bắt Wi-Fi gửi gói tin cho nhau). Khi đó 2 máy ping nhau sẽ bị `Destination Host Unreachable` hoặc `100% packet loss`.

**Giải pháp khắc phục 100% thành công:**
* **Cách 1 (Dễ nhất):** Dùng 1 điện thoại di động bật **Điểm phát sóng di động (Hotspot 4G)**. Cho cả 2 laptop cùng bắt vào Wi-Fi do điện thoại phát ra.
* **Cách 2:** Trên 1 máy tính Windows 11, bật tính năng **Mobile Hotspot** (Settings $\rightarrow$ Network & Internet $\rightarrow$ Mobile hotspot $\rightarrow$ On). Cho laptop thứ 2 kết nối vào Wi-Fi này.
* **Kết quả:** Hai laptop kết nối vào cùng mạng nội bộ không có tường lửa trung gian, gói tin truyền thông đi thẳng giữa 2 máy cực kỳ ổn định.

---

### 5. Tắt tạm thời Windows Firewall trên máy Host
Tường lửa của Windows Host (Windows Defender Firewall) đôi khi chặn các gói tin lạ đi xuyên từ card vật lý vào card ảo VMware (đặc biệt là gói tin phân mảnh IP Teardrop hoặc UDP 4789 của VXLAN).
* **Khuyến nghị:** Trong lúc thực hành demo, tạm thời tắt Firewall trên Windows của cả 2 máy (vào `Windows Security` $\rightarrow$ `Firewall & network protection` $\rightarrow$ tắt tạm thời ở `Private network` và `Public network`).

---

## III. QUY TRÌNH HEALTH CHECK KIỂM TRA THÔNG TUYẾN (BẮT BUỘC)

Trước khi thực hành bất kỳ bài lab nào, hãy thực hiện 2 bước sau:

1. **Bước 1: Lấy địa chỉ IP trên cả 2 máy**
   - Trên Máy 1: Gõ `hostname -I` $\rightarrow$ Giả sử nhận được: `192.168.1.50`
   - Trên Máy 2: Gõ `hostname -I` $\rightarrow$ Giả sử nhận được: `192.168.1.100`

2. **Bước 2: Ping kiểm tra thông mạng 2 chiều**
   - Từ Máy 1: `ping -c 2 192.168.1.100`
   - Từ Máy 2: `ping -c 2 192.168.1.50`
   - **Kết quả:** Cả 2 máy đều phản hồi `0% packet loss` $\rightarrow$ Hạ tầng mạng đã sẵn sàng 100%!

---

## IV. BẢNG TỔNG HỢP CÂU LỆNH CHUẨN XÁC KHI TRIỂN KHAI 2 MÁY VMWARE

*(Toàn bộ câu lệnh đều sử dụng card mạng `eth0` chuẩn của VMware)*

| Bài Lab | Trên Máy 2 (Victim / Server / Host - Card `eth0`) | Trên Máy 1 (Attacker / Client - Card `eth0`) |
|---|---|---|
| **Lab 01 (ISN & Spoofing)** | `python3 server_h2.py` | `sudo python3 isn_sampler.py <IP_M2>`<br>`sudo python3 spoof_sniff.py <IP_M2> <IP_SPOOF> eth0` |
| **Lab 02 (SSRR Source Route)** | `sudo sysctl -w net.ipv4.conf.all.accept_source_route=1 net.ipv4.conf.eth0.accept_source_route=1`<br>`sudo tcpdump -i eth0 -nn -v icmp` | `sudo python3 ssrr.py <IP_M2> <IP_M1> eth0` |
| **Lab 03 (ICMP Tunneling)** | `sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1`<br>`sudo iptables -F && sudo iptables -A INPUT -p tcp --dport 9999 -j DROP`<br>`sudo python3 icmp_server.py eth0` | `sudo python3 icmp_client.py <IP_M2> eth0` |
| **Lab 04 (Smurf Attack qua VXLAN)** | `sudo bash setup_lab4_2pc.sh host <IP_M1>`<br>*(Bật tcpdump trên victim)*:<br>`sudo ip netns exec vic tcpdump -i vic0 -nn icmp` | `sudo bash setup_lab4_2pc.sh attacker <IP_M2>`<br>*(Phát động bão Smurf)*:<br>`sudo ip netns exec atk python3 smurf_attack.py 10.0.0.200 10.0.0.255 atk0` |
| **Lab 05 (ICMP Redirect qua VXLAN)** | `sudo bash setup_lab5_2pc.sh host <IP_M1>`<br>*(Quan sát routing và ping từ victim)*:<br>`sudo ip netns exec vic ip route`<br>`sudo ip netns exec vic ping 10.0.1.5` | `sudo bash setup_lab5_2pc.sh attacker <IP_M2>`<br>*(Bắn Redirect bẻ lái & lắng nghe)*:<br>`sudo ip netns exec atk python3 redirect_attack.py 10.0.0.2 10.0.0.1 10.0.0.66 10.0.1.5 atk0` |
| **Lab 06 (Teardrop Attack)** | `netstat -s \| grep -i -E "reassembl\|fragments"`<br>`sudo tcpdump -i eth0 -nn -v 'ip[6:2] & 0x3fff != 0'` | `sudo python3 teardrop_attack.py <IP_M2> eth0`<br>`ping -c 3 <IP_M2>` |
| **Lab 07 (DNSSEC Validation)** | `sudo systemctl stop systemd-resolved`<br>`sudo bash setup_dnssec_configs_real.sh <IP_M2>`<br>`named -c /etc/bind/named-auth.conf -g &`<br>`bash setup_unbound_real.sh <IP_M2>`<br>`unbound -c /etc/unbound/unbound.conf -d &` | `dig @<IP_M2> www.lab.test +dnssec` |

