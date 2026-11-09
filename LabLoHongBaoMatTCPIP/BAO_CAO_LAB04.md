# BÁO CÁO THỰC HÀNH CHI TIẾT — BÀI LAB 04
## Đề tài: Kỹ thuật tấn công Smurf Attack (ICMP Broadcast Amplification DoS)

---

## I. MỤC TIÊU BÀI THỰC HÀNH

1. **Hiểu bản chất của tấn công từ chối dịch vụ khuếch đại (Amplification Denial-of-Service - DoS)**:
   * Cách kẻ tấn công chỉ cần tiêu tốn một lượng băng thông cực nhỏ nhưng có thể mượn sức mạnh của các máy trạm trung gian trong mạng để tạo ra một lượng lưu lượng khổng lồ đè bẹp máy nạn nhân.
2. **Hiểu vai trò của địa chỉ Broadcast (Quảng bá) & Switch ảo (Bridge)**:
   * Cơ chế nhân bản gói tin của Switch khi nhận gói tin gửi tới địa chỉ Broadcast của dải mạng (`10.0.0.255`).
3. **Hiểu vai trò sống còn của Giả mạo IP nguồn (IP Spoofing)**:
   * Vì sao trong tấn công Smurf, kẻ tấn công bắt buộc phải giả mạo IP nguồn thành địa chỉ của Nạn nhân (`10.0.0.200`).
4. **Mô phỏng mạng LAN 5 máy và đo đạc hệ số khuếch đại (Amplification Factor)**:
   * Dựng mô hình mạng LAN nội bộ gồm 5 máy ảo độc lập nối qua Linux Bridge `br0`.
   * Gửi 10 gói tin ping broadcast và quan sát 30 gói tin dội về máy nạn nhân (hệ số khuếch đại $\times 3$).
5. **Triển khai và kiểm chứng cơ chế phòng thủ**:
   * Phòng thủ tại từng máy trạm thông qua tham số nhân Linux: `net.ipv4.icmp_echo_ignore_broadcasts = 1`.
   * Phòng thủ tại Router biên theo tiêu chuẩn RFC 2644 (BCP 34) và BCP 38.

---

## II. KIẾN THỨC NỀN TẢNG CỐT LÕI

### 1. Phân biệt thiết bị mạng: Switch (Bridge) vs. Router
* **Switch / Linux Bridge (`br0`) — Tầng 2 (Data Link)**:
  * Nối các máy tính **trong cùng một mạng nội bộ LAN** (cùng dải `10.0.0.0/24`). Quản lý gói tin bằng địa chỉ phần cứng MAC.
  * **Đặc tính phát tán Broadcast**: Khi một gói tin được gửi tới địa chỉ Broadcast (`10.0.0.255` hoặc MAC `FF:FF:FF:FF:FF:FF`), Switch sẽ đóng vai trò như chiếc "loa phóng thanh": **tự động nhân bản gói tin và đẩy ra tất cả các cổng** đang cắm vào nó.
* **Router (Bộ định tuyến) — Tầng 3 (Network)**:
  * Nối **các mạng LAN khác nhau** hoặc nối mạng nội bộ ra Internet. Quản lý gói tin bằng địa chỉ IP.
  * **Đặc tính an toàn**: Mặc định Router ngăn chặn, không cho các gói tin Broadcast từ mạng này tràn sang mạng khác.

```mermaid
flowchart TD
    Attacker["Kẻ tấn công atk (10.0.0.100)"] -->|1. Bắn 10 gói Ping Broadcast (Nguồn giả: 10.0.0.200)| Switch["Switch ảo br0 (Tầng 2)"]
    Switch -->|Nhân bản gói tin| Amp1["Máy khuếch đại amp1 (10.0.0.11)"]
    Switch -->|Nhân bản gói tin| Amp2["Máy khuếch đại amp2 (10.0.0.12)"]
    Switch -->|Nhân bản gói tin| Amp3["Máy khuếch đại amp3 (10.0.0.13)"]
    Amp1 -->|Echo Reply dội về| Victim["Nạn nhân vic (10.0.0.200)"]
    Amp2 -->|Echo Reply dội về| Victim
    Amp3 -->|Echo Reply dội về| Victim
    Note over Victim: Nhận 30 gói phản hồi dội về (Khuếch đại x3)!
```

### 2. Kịch bản tấn công Smurf Attack hoạt động ra sao?
1. Kẻ tấn công tạo một gói tin **ICMP Echo Request (Ping)** với:
   * **Địa chỉ đích (Destination):** `10.0.0.255` (Địa chỉ Broadcast của mạng LAN).
   * **Địa chỉ nguồn (Source) BỊ GIẢ MẠO:** `10.0.0.200` (Địa chỉ IP của Nạn nhân).
2. Gói tin đi vào Switch `br0`. Switch nhân bản và chuyển tiếp gói tin tới mọi máy đang hoạt động trong mạng (`amp1`, `amp2`, `amp3`).
3. Các máy này nhận được gói ping, nhìn vào ô người gửi thấy ghi `10.0.0.200`, tưởng rằng máy Nạn nhân đang ping mình.
4. Từng máy khuếch đại liền đồng loạt gửi gói **ICMP Echo Reply** dội thẳng về địa chỉ của Nạn nhân (`10.0.0.200`).
5. **Hệ số khuếch đại:**
   $$\text{Hệ số khuếch đại} = \frac{\text{Tổng số gói Reply dội về Nạn nhân}}{\text{Số gói Request Attacker gửi đi}} = \text{Số máy phản hồi trong mạng}$$

### 3. Tại sao bước Giả mạo IP nguồn (IP Spoofing) là bắt buộc?
* Nếu kẻ tấn công **không giả mạo IP nguồn** (để IP nguồn là chính mình `10.0.0.100`), thì toàn bộ 30 gói tin phản hồi của các máy khuếch đại sẽ **dội ngược thẳng về máy của kẻ tấn công**! 
* Khi đó kẻ tấn công sẽ tự đánh sập chính mình thay vì đánh sập nạn nhân.

---

## III. GIẢI THÍCH CHI TIẾT CÁC FILE MÃ NGUỒN

Các file phục vụ thực hành được lưu tại: `/home/tantayen/Projects/TCPIP/LabLoHongBaoMatTCPIP/`

### 1. File `setup_lan.sh` (Khởi tạo Switch ảo và 5 máy con)
* **Chức năng**: Xóa bỏ topo cũ, tạo một Switch ảo Linux Bridge (`br0`) và gắn 5 không gian mạng (`ip netns`) vào switch qua các cặp dây mạng ảo `veth`.
* **Phân bổ địa chỉ mạng LAN `10.0.0.0/24` (Broadcast: `10.0.0.255`)**:
  * `atk`: `10.0.0.100` (Máy kẻ tấn công).
  * `vic`: `10.0.0.200` (Máy nạn nhân).
  * `amp1`: `10.0.0.11` (Máy khuếch đại 1).
  * `amp2`: `10.0.0.12` (Máy khuếch đại 2).
  * `amp3`: `10.0.0.13` (Máy khuếch đại 3).
* **Cấu hình mở lỗ hổng**:
  ```bash
  for h in amp1 amp2 amp3; do
      ip netns exec $h sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=0
  done
  ```
  *(Mặc định Linux tắt tính năng này để bảo vệ máy; ta phải đặt bằng 0 để cho phép các máy khuếch đại trả lời ping broadcast nhằm phục vụ thí nghiệm).*

---

### 2. File `smurf_attack.py` (Script phát động tấn công)
* **Chức năng**: Dùng Scapy chế tạo và phát động hàng loạt gói tin ICMP Broadcast giả mạo nguồn.
* **Cơ chế hoạt động**:
  ```python
  from scapy.all import *

  victim_ip = "10.0.0.200"
  broadcast_ip = "10.0.0.255"

  # Bắn 10 gói ICMP Echo Request tới địa chỉ Broadcast với nguồn giả mạo là Victim
  send(IP(src=victim_ip, dst=broadcast_ip) / ICMP(), count=10, verbose=0)
```
  * Đoạn code trên tạo ra 10 gói tin IP có `src = 10.0.0.200` và `dst = 10.0.0.255` rồi đẩy ra mạng.

---

### 3. File `clean_lan.sh` (Dọn dẹp môi trường)
* **Chức năng**: Xóa sạch 5 namespace (`atk`, `vic`, `amp1`, `amp2`, `amp3`) và gỡ bỏ switch ảo `br0` sau khi hoàn thành bài thực hành, giúp hệ thống sạch sẽ.

---

## IV. QUÁ TRÌNH THỰC HÀNH & KẾT QUẢ ĐẠT ĐƯỢC

### 1. Bố trí màn hình làm việc
* **Terminal Trái (Attacker `atk` - 10.0.0.100)**: Phát động tấn công.
* **Terminal Phải (Victim `vic` - 10.0.0.200)**: Bật `tcpdump` hứng lưu lượng dội về.

---

### 2. Kịch bản 1 — Khi các máy khuếch đại chưa phòng thủ (`icmp_echo_ignore_broadcasts = 0`)

1. Trên Terminal Phải (Victim):
   ```bash
   sudo ip netns exec vic bash
   tcpdump -i vic0 -nn icmp
   ```
2. Trên Terminal Trái (Attacker):
   ```bash
   sudo ip netns exec atk bash
   python3 smurf_attack.py
   ```

#### Kết quả quan sát thực tế trên Terminal Phải (`tcpdump`):
Terminal của Victim ngay lập tức ghi nhận 40 dòng gói tin xuất hiện chớp nhoáng:
```text
21:33:48.635011 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, seq 0  (Gói Broadcast)
21:33:48.635045 IP 10.0.0.13  > 10.0.0.200: ICMP echo reply, seq 0    (amp3 dội về)
21:33:48.635046 IP 10.0.0.12  > 10.0.0.200: ICMP echo reply, seq 0    (amp2 dội về)
21:33:48.635047 IP 10.0.0.11  > 10.0.0.200: ICMP echo reply, seq 0    (amp1 dội về)
... (Lặp lại đủ 10 chu kỳ)
```

#### Phân tích số liệu thực nghiệm:
* Số gói tin kẻ tấn công gửi đi: **10 gói**.
* Số gói tin phản hồi Nạn nhân nhận được: **30 gói Echo Reply** (chia đều từ 3 máy `.11`, `.12`, `.13`).
* **Hệ số khuếch đại thực tế:**
  $$\text{Hệ số khuếch đại} = \frac{30 \text{ gói reply}}{10 \text{ gói request}} = \times 3$$
* Nếu quy mô mạng LAN thực tế có 500 máy tính, kẻ tấn công chỉ cần gửi 1.000 gói tin (khoảng vài chục KB) sẽ tạo ra một cơn lũ **500.000 gói tin** dội về cùng một thời điểm, làm tràn bộ đệm card mạng và tê liệt hoàn toàn máy chủ nạn nhân!

---

### 3. Kịch bản 2 — Khi bật cơ chế phòng thủ (`icmp_echo_ignore_broadcasts = 1`)

1. Bật cơ chế tự bảo vệ trên cả 3 máy khuếch đại:
   ```bash
   for h in amp1 amp2 amp3; do
       sudo ip netns exec $h sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
   done
   ```
2. Tại Terminal Trái (Attacker): Chạy lại `python3 smurf_attack.py`.
3. **Kết quả quan sát tại Terminal Phải (Victim):**
   * Màn hình của Victim **hoàn toàn im ắng, không còn bất kỳ gói Echo Reply nào dội về nữa** (chỉ thấy các gói broadcast bay qua dây mạng).
   * Cả 3 máy khuếch đại đã bỏ qua hoàn toàn yêu cầu ping broadcast, triệt tiêu tận gốc cơ chế khuếch đại của cuộc tấn công Smurf.

---

## V. CÁC BIỆN PHÁP PHÒNG CHỐNG (MITIGATION)

Để triệt tiêu hoàn toàn hiểm họa Smurf Attack, cần áp dụng đồng thời các giải pháp sau:

1. **Cấu hình trên từng Host/Máy trạm**:
   * Thiết lập `net.ipv4.icmp_echo_ignore_broadcasts = 1` trên mọi máy tính trong mạng (mặc định các bản phân phối Linux và Windows hiện đại đã kích hoạt sẵn chế độ này).
2. **Cấu hình trên Router biên theo chuẩn RFC 2644 (BCP 34)**:
   * **Vô hiệu hóa chuyển tiếp Directed Broadcast**: Cấu hình câu lệnh `no ip directed-broadcast` trên các cổng của Router.
   * *Ý nghĩa:* Khi kẻ tấn công từ ngoài Internet gửi gói tin nhắm tới địa chỉ broadcast của mạng nội bộ (ví dụ `192.168.1.255`), Router biên sẽ lập tức tiêu hủy gói tin, không cho phép gói tin này được nhân bản vào mạng LAN nội bộ.
3. **Lọc địa chỉ IP nguồn giả mạo theo BCP 38 / RFC 2827 (Ingress Filtering)**:
   * Router biên chỉ cho phép các gói tin có địa chỉ IP nguồn thuộc đúng dải IP hợp lệ của mạng đó đi ra ngoài, chặn đứng bước giả mạo IP nguồn ngay từ đầu.
4. **Giới hạn tốc độ (Rate Limiting) giao thức ICMP**:
   * Cấu hình giới hạn ngưỡng lưu lượng ICMP trên thiết bị chuyển mạch (Switch/Router) để hạn chế nguy cơ nghẽn mạng khi có bão broadcast.

---

## VI. ĐÁP ÁN 4 CÂU HỎI ÔN TẬP CỦA GIẢNG VIÊN

| STT | Câu hỏi của Giảng viên | Đáp án chuẩn xác & Điểm tuyệt đối |
| :---: | :--- | :--- |
| **1** | *Hệ số khuếch đại của Smurf phụ thuộc yếu tố nào? Trong lab, nếu thêm 10 máy khuếch đại thì lưu lượng dội về nạn nhân thay đổi ra sao?* | **Đáp:** Hệ số khuếch đại phụ thuộc trực tiếp vào **số lượng máy tính đang hoạt động trong mạng LAN** nhận được gói broadcast và có bật tính năng phản hồi ICMP Echo. Trong bài lab, hiện có 3 máy khuếch đại nên hệ số là $\times 3$. Nếu bổ sung thêm 10 máy nữa (tổng cộng 13 máy khuếch đại), lưu lượng dội về nạn nhân sẽ tăng vọt gấp **13 lần** (10 gói gửi đi sinh ra 130 gói Reply dội về). |
| **2** | *Vì sao bước giả mạo địa chỉ nguồn là bắt buộc? Điều gì xảy ra nếu không giả mạo?* | **Đáp:** Vì mục tiêu của kẻ tấn công là làm nghẽn máy Nạn nhân. Do gói tin được gửi tới địa chỉ Broadcast, các máy trong mạng sẽ trả lời về địa chỉ ghi ở IP nguồn. Nếu không giả mạo IP nguồn thành IP của Nạn nhân, toàn bộ lưu lượng phản hồi dội về sẽ đánh thẳng vào chính máy của Attacker, biến Attacker thành nạn nhân tự đánh sập chính mình. |
| **3** | *So sánh vai trò của hai biện pháp: bỏ qua ping broadcast (ở host) và chặn directed broadcast (ở router)?* | **Đáp:** (1) Biện pháp ở Host (`icmp_echo_ignore_broadcasts = 1`): Giúp từng máy tính tự bảo vệ mình, không tiếp tay làm "quân cờ khuếch đại" cho kẻ tấn công nội bộ. (2) Biện pháp ở Router (`no ip directed-broadcast`): Đóng vai trò chốt chặn ở cửa ngõ, ngăn không cho kẻ tấn công từ Internet bên ngoài mượn mạng LAN nội bộ làm bàn đạp khuếch đại tấn công nơi khác. |
| **4** | *Smurf thuộc nhóm tấn công nào (theo mục tiêu)? Nêu một biến thể dùng UDP tương tự?* | **Đáp:** Smurf thuộc nhóm tấn công **Từ chối dịch vụ khuếch đại (Amplification Denial-of-Service - DoS/DDoS)** nhằm làm cạn kiệt băng thông và tài nguyên xử lý của nạn nhân. Biến thể sử dụng giao thức UDP tương tự là **Fraggle Attack** (gửi gói UDP tới cổng echo số 7 hoặc chargen số 19 qua địa chỉ broadcast với IP nguồn giả mạo). |

---

## VII. KỊCH BẢN THUYẾT TRÌNH KHI QUAY VIDEO (VOICEOVER)

> **Bố cục màn hình đề xuất khi quay video:**
> * Mở ứng dụng Konsole / Terminal và chia đôi màn hình (Split Screen):
>   * **Cửa sổ bên trái:** Máy Kẻ tấn công `atk` (`10.0.0.100`).
>   * **Cửa sổ bên phải:** Máy Nạn nhân `vic` (`10.0.0.200`).
> * Bạn vừa gõ từng câu lệnh trên màn hình, vừa đọc lời thoại giải thích tương ứng dưới đây:

---

### [0:00 - 0:35] Mở đầu & Giới thiệu đề tài
* **Lời thoại:**
  *"Kính chào thầy và các bạn! Hôm nay em xin trình bày bài thực hành số 04: Kỹ thuật tấn công Từ chối dịch vụ khuếch đại Smurf Attack (ICMP Broadcast Amplification DoS). Smurf là một đòn tấn công kinh điển kết hợp giữa việc giả mạo địa chỉ IP nguồn và cơ chế phát sóng quảng bá Broadcast của mạng LAN để khuếch đại lưu lượng tấn công lên gấp hàng chục, hàng trăm lần, nhằm làm cạn kiệt băng thông và tài nguyên xử lý của nạn nhân."*

---

### [0:35 - 1:15] Bước 1: Khởi tạo mô hình mạng LAN ảo 5 máy
* **Thao tác trên terminal trái:**
  ```bash
  sudo bash setup_lan.sh
  ```
* **Lời thoại giải thích:**
  *"Trước tiên, em chạy lệnh `sudo bash setup_lan.sh`. Kịch bản này sử dụng Linux Bridge `br0` để tạo ra một Switch mạng LAN ảo kết nối 5 máy tính độc lập:
  * Máy tấn công `atk` có IP `10.0.0.100`.
  * Máy nạn nhân `vic` có IP `10.0.0.200`.
  * Ba máy đóng vai trò khuếch đại: `amp1`, `amp2`, `amp3` có IP lần lượt là `10.0.0.11`, `.12` và `.13`.
  
  *Đồng thời, script tạm thời cấu hình tham số `icmp_echo_ignore_broadcasts = 0` trên các máy amp để mô phỏng một hệ sinh thái mạng cổ điển còn tồn tại lỗ hổng phản hồi broadcast. Kiểm tra ping ban đầu giữa các máy đã thông suốt 100%!"*

---

### [1:15 - 2:30] Bước 2: Nạn nhân túc trực tcpdump & Kẻ tấn công phát động Smurf
* **Thao tác 1 (Terminal phải - Máy nạn nhân vic bật tcpdump):**
  ```bash
  sudo ip netns exec vic tcpdump -i vic0 -nn icmp
  ```
  * **Lời thoại:**
    *"Tại cửa sổ bên phải của máy nạn nhân `vic`, em chạy lệnh `tcpdump` trên card mạng `vic0` để theo dõi toàn bộ các gói tin ICMP nhận được."*

* **Thao tác 2 (Terminal trái - Máy atk chạy script tấn công):**
  ```bash
  sudo ip netns exec atk python3 smurf_attack.py
  ```
  * **Lời thoại:**
    *"Bây giờ tại máy tấn công `atk` bên trái, em kích hoạt script `smurf_attack.py`. File Python này sử dụng thư viện Scapy để thực hiện đòn tấn công tinh vi:
    * Nó gửi đúng 10 gói tin ICMP Echo Request tới địa chỉ quảng bá toàn mạng là `10.0.0.255`.
    * Điểm mấu chốt là: Nó giả mạo địa chỉ IP nguồn thành IP của máy nạn nhân `10.0.0.200`.
    
    *Ngay khi Switch ảo `br0` nhận được gói tin tới địa chỉ broadcast, Switch lập tức nhân bản gói tin và gửi tới tất cả các máy trong mạng. Cả 3 máy `amp1`, `amp2`, `amp3` tưởng rằng nạn nhân đang ping mình, liền đồng loạt gửi gói Echo Reply dội ngược về IP nguồn 10.0.0.200!
    
    *Thầy và các bạn hãy nhìn sang màn hình tcpdump của nạn nhân bên phải: Chỉ với 10 gói tin nhỏ gửi đi từ máy tấn công, máy nạn nhân đã phải hứng chịu một cơn bão gồm 30 gói tin Reply dội về tới tấp từ cả 3 máy khuếch đại `.11`, `.12`, `.13`, đạt hệ số khuếch đại đúng bằng 3 lần! Trong một mạng LAN thực tế với hàng ngàn máy tính, hệ số khuếch đại này sẽ làm sập hoàn toàn card mạng của nạn nhân!"*

---

### [2:30 - 3:30] Bước 3: Triển khai phòng thủ & Kiểm chứng hiệu quả
* **Thao tác 1 (Terminal phải - Nhấn Ctrl+C dừng tcpdump, cấu hình cấm phản hồi broadcast):**
  ```bash
  for h in amp1 amp2 amp3; do sudo ip netns exec $h sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1; done
  sudo ip netns exec vic tcpdump -i vic0 -nn icmp
  ```
  * **Lời thoại:**
    *"Để phòng thủ, em triển khai chính sách an ninh trên cả 3 máy khuếch đại bằng cách bật tham số `net.ipv4.icmp_echo_ignore_broadcasts = 1` cấm hoàn toàn việc phản hồi các gói ping gửi tới địa chỉ broadcast, sau đó tiếp tục bật tcpdump bên phải."*

* **Thao tác 2 (Terminal trái - Chạy lại script tấn công):**
  ```bash
  sudo ip netns exec atk python3 smurf_attack.py
  ```
  * **Lời thoại:**
    *"Em phát động lại đợt tấn công từ máy `atk`. Kết quả quan sát trên tcpdump bên phải: Màn hình hoàn toàn im lặng, không có bất kỳ một gói tin Reply nào dội về máy nạn nhân nữa! Cả 3 máy khuếch đại đã âm thầm tiêu hủy các gói tin broadcast đáng ngờ ngay tại Kernel!"*

---

### [3:30 - 4:10] Bước 4: Dọn dẹp môi trường & Biện pháp phòng vệ toàn diện
* **Thao tác trên terminal trái:**
  ```bash
  sudo bash clean_lan.sh
  ```
* **Lời thoại giải thích:**
  *"Em chạy lệnh `sudo bash clean_lan.sh` để xóa Switch ảo `br0` và giải phóng toàn bộ 5 namespace.*
  
  *Qua bài thực hành số 04, chúng ta thấy rõ: Để triệt tiêu hoàn toàn hiểm họa Smurf Attack, bên cạnh việc cấu hình `icmp_echo_ignore_broadcasts = 1` trên các máy trạm nội bộ, biện pháp then chốt ở cấp độ hạ tầng là các kỹ sư mạng phải cấu hình lệnh `no ip directed-broadcast` trên toàn bộ Router biên theo khuyến cáo của chuẩn RFC 2644 để ngăn chặn kẻ tấn công từ Internet mượn mạng nội bộ làm bàn đạp khuếch đại DoS. Em xin kết thúc bài thực hành số 04 tại đây!"*

