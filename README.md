### Bài tập môn AN toàn và bảo mật thông tin.
  
## Họ và tên: Phan Văn Hải
## Lớp: K59.KTP

Bài 1: Mã hoá AES : Mã hoá đối xứng (mã hoá, giải mã cùng dùng 1 khoá)

#  CÀI ĐẶT MÔI TRƯỜNG

### Tải Visual Studio 2022 Community

Vào trang `visualstudio.microsoft.com`, chọn **Community 2022** và tải bộ cài về.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/31defa26-6bb3-45f3-b8f2-f565906f1ba7" />


###  Chọn workload khi cài

Chạy bộ cài, tick workload **".NET desktop development"**, rồi nhấn **Install**.



### Kiểm tra .NET 8

Mở **Command Prompt** và gõ:

```bash
dotnet --version
```

### Tạo solution và project Console

1. Mở Visual Studio → **Create a new project**.

2. Chọn **Console App** (C#) → **Next**.

3. Đặt tên project `AesConsole`, solution `Bai1_AES` → **Next**.

4. Chọn Framework **.NET 8.0** → **Create**.


### Bước 1.2: Thêm file `AesService.cs`

1. Trong **Solution Explorer**, chuột phải project `AesConsole` → **Add** → **Class**.
2. Đặt tên `AesService.cs` → **Add**.
3. Xoá toàn bộ nội dung có sẵn, dán code `AesService.cs` ở mục 1.3 của file `Bai_tap_ATBMTT_AES_RSA.md`.

> 📷 **CHÈN ẢNH:** Solution Explorer thấy file `AesService.cs` và code đã dán.

### Bước 1.3: Dán code `Program.cs`

Mở `Program.cs`, xoá nội dung cũ, dán code `Program.cs` của project `AesConsole` (mục 1.3).

> 📷 **CHÈN ẢNH:** file `Program.cs` sau khi dán code.

### Bước 1.4: Chuyển sang chế độ Release và chạy

1. Ở thanh công cụ phía trên, đổi ô **Debug** thành **Release**.
2. Nhấn **Ctrl + F5** (Start Without Debugging).

> 📷 **CHÈN ẢNH:** thanh công cụ với ô cấu hình đang là **Release**.
> 📷 **CHÈN ẢNH:** cửa sổ console hiện menu "AES-256 (CONSOLE)".

### Bước 1.5: Chức năng 1 – Sinh khoá AES

Gõ `1` → Enter. Chương trình in khoá 256 bit dạng Base64 (44 ký tự).

> 📷 **CHÈN ẢNH:** console sau khi chọn 1, hiện khoá Base64.

### Bước 1.6: Chức năng 2 – Lưu khoá ra file

Gõ `2` → Enter → Enter (dùng tên mặc định `aes.key`). File nằm trong thư mục `bin\Release\net8.0\`.

> 📷 **CHÈN ẢNH:** console báo "Đã lưu khoá".
> 📷 **CHÈN ẢNH:** File Explorer thấy file `aes.key`, và nội dung file mở bằng Notepad.

### Bước 1.7: Chức năng 3 – Nạp khoá từ file

Gõ `3` → Enter → Enter. Khoá hiện ở dòng "Khoá hiện tại" phải **trùng** khoá đã sinh ở bước 1.5.

> 📷 **CHÈN ẢNH:** console báo "Đã nạp khoá 256 bit".

### Bước 1.8: Chức năng 4 – Mã hoá một đoạn văn bản

Gõ `4` → Enter, nhập ví dụ: `Xin chao, day la bai tap AES`. Chương trình in bản mã (Base64) và giải mã lại ra đúng văn bản gốc.

> 📷 **CHÈN ẢNH:** console hiện bản mã Base64 và dòng "Giải mã lại".

### Bước 1.9: Chức năng 5 – Mã hoá một file

1. Tạo file `test.txt` bất kỳ (ví dụ vài dòng chữ), để cùng thư mục chạy.
2. Gõ `5` → Enter → nhập `test.txt` → Enter → Enter (file đích mặc định `test.txt.enc`).

> 📷 **CHÈN ẢNH:** console báo "Mã hoá xong trong ... s".
> 📷 **CHÈN ẢNH:** File Explorer thấy `test.txt` và `test.txt.enc`; mở `.enc` bằng Notepad thấy toàn ký tự lạ.

### Bước 1.10: Chức năng 6 – Giải mã file

Gõ `6` → Enter → nhập `test.txt.enc` → Enter → Enter (file đích mặc định `test.txt.enc.dec`).

> 📷 **CHÈN ẢNH:** console báo giải mã xong; mở file `.dec` bằng Notepad thấy nội dung giống `test.txt`.

### Bước 1.11: Chức năng 7 – Thử nghiệm file lớn (hàng GB)

> **Chuẩn bị:** ổ đĩa còn trống ít nhất **3 lần dung lượng** file thử nghiệm (nguồn + .enc + .dec). Ví dụ file 4 GB cần ~12 GB trống.

Thực hiện lần lượt cho các cỡ **0.1 → 0.5 → 1 → 2 → 4 GB**:

1. Gõ `7` → Enter.
2. Để trống ô đường dẫn (Enter) để tự tạo file ngẫu nhiên.
3. Nhập dung lượng, ví dụ `1` (dùng dấu **chấm** cho số thập phân, ví dụ `0.5`).
4. Chờ chạy xong, ghi số liệu vào bảng ở Bước 1.12.

> 📷 **CHÈN ẢNH 1:** console đang tạo file thử nghiệm (1 GB).
> 📷 **CHÈN ẢNH 2:** bảng "KẾT QUẢ" của file 1 GB (thời gian mã hoá, giải mã, MB/s, so sánh byte).
> 📷 **CHÈN ẢNH 3:** bảng "KẾT QUẢ" của file 2 GB hoặc 4 GB.
> 📷 **CHÈN ẢNH 4:** Task Manager lúc đang mã hoá, cho thấy RAM của chương trình chỉ vài chục MB.

### Bước 1.12: Điền bảng số liệu

Cấu hình máy: CPU `........` – RAM `....` GB – Ổ đĩa `SSD/HDD ......`.

| Dung lượng | Mã hoá (s) | Giải mã (s) | Tốc độ mã hoá (MB/s) | Tốc độ giải mã (MB/s) | So sánh byte |
|---|---|---|---|---|---|
| 100 MB | | | | | |
| 500 MB | | | | | |
| 1 GB | | | | | |
| 2 GB | | | | | |
| 4 GB | | | | | |

### Bước 1.13: Kết luận

Chép phần kết luận ở mục 1.4 của file `Bai_tap_ATBMTT_AES_RSA.md` và đối chiếu với bảng trên: thời gian tăng tuyến tính theo dung lượng, tốc độ mã hoá ≈ giải mã, so sánh byte giống nhau 100%, bộ nhớ gần như không đổi.

---

## PHẦN 2 – BÀI 1: AES BẢN FORM

### Bước 2.1: Thêm project Windows Forms vào solution

1. Chuột phải **Solution** `Bai1_AES` → **Add** → **New Project**.
2. Chọn **Windows Forms App** (C#, không phải ".NET Framework") → đặt tên `AesForm` → Framework **.NET 8.0**.

> 📷 **CHÈN ẢNH:** màn hình chọn template "Windows Forms App".

### Bước 2.2: Dán code

1. Xoá file `Form1.cs`, `Form1.Designer.cs` và `Program.cs` có sẵn của project `AesForm`.
2. Thêm file `AesService.cs` (dán lại đúng code ở Bước 1.2, hoặc dùng *Add → Existing Item → Add As Link* để dùng chung).
3. Thêm class `MainForm.cs`, dán code `MainForm.cs` ở mục 1.3 (file này đã có sẵn hàm `Main`).

> 📷 **CHÈN ẢNH:** Solution Explorer của project `AesForm` với 2 file `AesService.cs` và `MainForm.cs`.

### Bước 2.3: Đặt project Form làm Startup, chạy Release

Chuột phải project `AesForm` → **Set as Startup Project** → chọn **Release** → **Ctrl + F5**.

> 📷 **CHÈN ẢNH:** giao diện form AES khi mới mở.

### Bước 2.4: Sinh, lưu, nạp khoá

1. Nhấn **Sinh khoá 256 bit** → khoá Base64 hiện trong ô.
2. Nhấn **Lưu khoá ra file** → lưu `aes.key`.
3. Nhấn **Nạp khoá từ file** → chọn `aes.key`.

> 📷 **CHÈN ẢNH 1:** form sau khi sinh khoá.
> 📷 **CHÈN ẢNH 2:** hộp thoại lưu khoá.
> 📷 **CHÈN ẢNH 3:** nhật ký báo "Đã nạp khoá 256 bit".

### Bước 2.5: Mã hoá và giải mã văn bản

Nhập văn bản vào ô trên → nhấn **Mã hoá văn bản ↓** → bản mã Base64 hiện ở ô dưới. Xoá ô trên, nhấn **Giải mã bản mã ↑** → văn bản gốc hiện lại.

> 📷 **CHÈN ẢNH 1:** form sau khi mã hoá (ô dưới có bản mã).
> 📷 **CHÈN ẢNH 2:** form sau khi giải mã (ô trên có văn bản gốc).

### Bước 2.6: Mã hoá file, giải mã file, so sánh byte

1. Nhấn **Chọn...** → chọn file nguồn (có thể dùng file `test_1GB.bin` tạo ở Bước 1.11).
2. Nhấn **Mã hoá file → .enc** → chờ, nhật ký ghi thời gian và MB/s.
3. Nhấn **Giải mã .enc → .dec**.
4. Nhấn **So sánh byte nguồn ↔ .dec** → phải ra "GIỐNG NHAU 100%".

> 📷 **CHÈN ẢNH 1:** form có đường dẫn file nguồn và thanh chạy khi đang mã hoá.
> 📷 **CHÈN ẢNH 2:** ô nhật ký với thời gian mã hoá, giải mã, kết quả so sánh byte.

---

