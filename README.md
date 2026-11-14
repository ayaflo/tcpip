# Chuyên Đề: Lỗ Hổng Bảo Mật & Kỹ Thuật Tấn Công Giao Thức TCP/IP

Kho lưu trữ toàn bộ mã nguồn, kịch bản tự động hóa (`.sh`, `.py`) và báo cáo thực hành chi tiết cho **7 bài lab chuyên sâu về An toàn Giao thức TCP/IP**.

---

## 📌 Danh Sách Các Bài Lab & Báo Cáo Chi Tiết

| STT | Tên Bài Lab | Đề Tài & Kỹ Thuật Nghiên Cứu | Báo Cáo Chi Tiết |
| :---: | :--- | :--- | :---: |
| **01** | **TCP Sequence Number Prediction & IP Spoofing** | Đoán số thứ tự ban đầu TCP ISN (RFC 6528) & Tấn công giả mạo IP On-path | [Xem Báo Cáo](LabLoHongBaoMatTCPIP/BAO_CAO_LAB01.md) |
| **02** | **IP Strict Source Route (SSRR)** | Lỗ hổng định tuyến tại nguồn nghiêm ngặt & Bẻ lái đường truyền hai chiều | [Xem Báo Cáo](LabLoHongBaoMatTCPIP/BAO_CAO_LAB02.md) |
| **03** | **ICMP Tunneling (Covert Channel)** | Kỹ thuật tạo kênh ngầm tuồn dữ liệu mật xuyên tường lửa (Data Exfiltration) | [Xem Báo Cáo](LabLoHongBaoMatTCPIP/BAO_CAO_LAB03.md) |
| **04** | **Smurf Attack (ICMP Broadcast Amplification)** | Tấn công từ chối dịch vụ khuếch đại lưu lượng qua địa chỉ Broadcast | [Xem Báo Cáo](LabLoHongBaoMatTCPIP/BAO_CAO_LAB04.md) |
| **05** | **ICMP Redirect Attack (Route Hijacking)** | Tấn công chiếm quyền định tuyến & Đứng giữa nghe lén (Man-in-the-Middle) | [Xem Báo Cáo](LabLoHongBaoMatTCPIP/BAO_CAO_LAB05.md) |
| **06** | **Teardrop Attack (Overlapping IP Fragments DoS)** | Phân mảnh IP chồng lấn & Kiểm chứng tính miễn nhiễm của Linux Kernel | [Xem Báo Cáo](LabLoHongBaoMatTCPIP/BAO_CAO_LAB06.md) |
| **07** | **DNSSEC (DNS Security Extensions)** | Triển khai và kiểm thực chữ ký số tên miền chống Cache Poisoning & Spoofing | [Xem Báo Cáo](LabLoHongBaoMatTCPIP/BAO_CAO_LAB07.md) |

---

## 📚 Tài Liệu Hướng Dẫn & Cẩm Nang
* **[Cẩm Nang Toàn Diện Chinh Phục Lab TCP/IP](cam_nang.md)**: Hướng dẫn từ A-Z về kiến trúc mạng, câu hỏi vấn đáp và mẹo thực hành trên Linux Network Namespaces (`ip netns`).
* **[Hướng Dẫn Triển Khai Trên 2 Máy Thật (Wi-Fi / Hotspot)](LabLoHongBaoMatTCPIP/HUONG_DAN_TRIEN_KHAI_2_MAY_THAT.md)**: Hướng dẫn chi tiết chạy thực nghiệm trên 2 laptop vật lý kết nối Wi-Fi, sử dụng công nghệ VXLAN Overlay (RFC 7348) để trao đổi gói tin thực chiến giữa 2 máy.
* **[Bộ Kịch Bản Tự Động Hóa Cho 2 Laptop](LabLoHongBaoMatTCPIP/)**:
  * `setup_lab4_2pc.sh`: Triển khai Lab 04 (Smurf) trên 2 laptop (Host: Nạn nhân + 3 trạm khuếch đại, Attacker: Laptop 2).
  * `setup_lab5_2pc.sh`: Triển khai Lab 05 (ICMP Redirect) trên 2 laptop (Host: Nạn nhân + Gateway + Đích, Attacker: Laptop 2 chiếm quyền MITM).
  * `setup_pair_2pc.sh`: Triển khai Lab 01, 02, 03, 06 giữa 2 laptop (Host `h2` và Guest `h1`).
  * `setup_dns_2pc.sh`: Triển khai Lab 07 (DNSSEC) giữa 2 laptop (Host DNS Servers và Guest Client dig).
  * `clean_2pc.sh`: Dọn dẹp sạch sẽ kết nối 2 máy tính.
* **[Lưu Ý Kỹ Thuật (VMware Win 11 vs Boot Ổ Rời)](LabLoHongBaoMatTCPIP_2MayThat/LUU_Y_TRIEN_KHAI_VMWARE_VS_MAY_THAT.md)**: Cấu hình card Bridged, tên interface `eth0` vs `wlan0`, phân vai Server/Attacker và xử lý xung đột cổng 53.

---

## 🛠️ Công Cụ & Môi Trường Thực Hành
* **Hệ điều hành:** Kali Linux / Ubuntu Linux
* **Bộ giả lập mạng:** Linux Network Namespaces (`ip netns`), Linux Virtual Ethernet (`veth`), Linux Bridge (`br0`)
* **Chế tạo gói tin:** Python 3 & thư viện `Scapy`
* **Giám sát lưu lượng:** `tcpdump`, `wireshark`
* **Dịch vụ mạng:** BIND9, Unbound Resolver, Netcat (`nc`), Socket TCP/UDP Python

