### Bài tập môn AN toàn và bảo mật thông tin.
  
## Họ và tên: Phan Văn Hải
## Lớp: K59.KTP

Bài 1: Mã hoá AES : Mã hoá đối xứng (mã hoá, giải mã cùng dùng 1 khoá)

#  CÀI ĐẶT MÔI TRƯỜNG

### Tải Visual Studio 2022 Community

Vào trang `visualstudio.microsoft.com`, chọn **Community 2022** và tải bộ cài về.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/31defa26-6bb3-45f3-b8f2-f565906f1ba7" />

### Kiểm tra .NET 8

Mở **Command Prompt** và gõ:

```bash
dotnet --version
```

### Tạo solution và project Console

 Mở Visual Studio → **Create a new project**.

Chọn **Console App** (C#) → **Next**.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/50cd7f18-1b09-48a3-b581-ac315b1b9bfa" />

 Đặt tên project `AesConsole`, solution `Bai1_AES` → **Next**.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/cc8355e4-3174-4ea4-a4f2-63e81435bda6" />

Chọn Framework **.NET 8.0** → **Create**.

<img width="1917" height="1077" alt="image" src="https://github.com/user-attachments/assets/3ebc4dfa-52cd-4a5a-ba9a-694d70e54c6c" />


AES (Advanced Encryption Standard) là mã hoá đối xứng: dùng cùng một khoá để mã hoá và giải mã. AES mã hoá theo khối 128 bit (16 byte), khoá có thể 128, 192 hoặc 256 bit. Bài này dùng **AES-256** (khoá 32 byte).

**Chế độ hoạt động được chọn: AES-CBC + PKCS7 padding.**

- Dữ liệu được chia thành các khối 16 byte; khối cuối được đệm (padding) cho đủ 16 byte.

- Cần một **IV (Initialization Vector) 16 byte ngẫu nhiên** cho mỗi lần mã hoá. IV không cần giữ bí mật, nên được ghi ngay đầu file/chuỗi mã hoá để giải mã đọc lại.

- Nhờ IV ngẫu nhiên, cùng một nội dung mã hoá 2 lần sẽ ra 2 kết quả khác nhau.

**Định dạng đầu ra dùng trong bài:**

```text
[ IV (16 byte) ][ Ciphertext (bội số của 16 byte) ]
```

Kích thước bản mã = 16 + (L / 16 + 1) × 16 byte, với L là kích thước bản rõ (phép chia nguyên). Như vậy bản mã lớn hơn bản rõ từ 17 đến 32 byte.

---

## Ý 1: Sinh khoá AES

### Phân tích

- Khoá AES phải là chuỗi byte **ngẫu nhiên an toàn về mật mã**, không được tự đặt kiểu "12345678".

- Độ dài khoá hợp lệ: 16, 24 hoặc 32 byte. Chọn 32 byte (256 bit).

- Trong .NET dùng `Aes.Create()` rồi `GenerateKey()`; hàm này gọi bộ sinh số ngẫu nhiên mật mã của hệ điều hành.

### Các bước làm

**Bước 1.** Tạo đối tượng `Aes.Create()`.

**Bước 2.** Đặt `KeySize = 256`.

**Bước 3.** Gọi `GenerateKey()` rồi lấy `aes.Key` (mảng 32 byte), lưu vào biến `_key` dùng chung.

**Bước 4.** In khoá dạng Base64 ra màn hình để quan sát.

---
<img width="1917" height="1077" alt="image" src="https://github.com/user-attachments/assets/d16cb55c-9ab3-45cc-80e3-74b99c3ba724" />

Sinh khóa tự động

## 1.2. Lưu khoá ra file

### Phân tích

- Khoá là mảng byte nhị phân, không ghi thẳng ra file text được an toàn, nên chuyển sang **Base64** (chuỗi 44 ký tự cho khoá 32 byte).

- Người dùng chọn đường dẫn file; mặc định `aes.key`.

- Lưu ý bảo mật: file khoá là bí mật, không đưa lên Git.

### Các bước làm

**Bước 1.** Kiểm tra đã có khoá (`_key != null`), nếu chưa thì báo lỗi.

**Bước 2.** Hỏi đường dẫn file.

**Bước 3.** `Convert.ToBase64String(_key)` rồi `File.WriteAllText`.

---
<img width="1526" height="1078" alt="image" src="https://github.com/user-attachments/assets/5fca4006-25df-4e39-b1b7-2b3c2a5ab8bf" />

Lưu khóa ra 1 file

## Import khoá từ file

### Phân tích

- Thao tác ngược của ý 2: đọc chuỗi Base64, giải về mảng byte.

- Phải **kiểm tra độ dài** là 16, 24 hoặc 32 byte, nếu không thì file khoá hỏng hoặc sai.

### Các bước làm

**Bước 1.** Hỏi đường dẫn file khoá.

**Bước 2.** `File.ReadAllText` rồi `Convert.FromBase64String`.

**Bước 3.** Kiểm tra độ dài hợp lệ, gán vào `_key`.

Nạp khóa từ file 

<img width="1866" height="1078" alt="image" src="https://github.com/user-attachments/assets/253f34fd-3a7d-43af-8240-f13bf72f8c4b" />

---

## Ý 4: Mã hoá một đoạn văn bản, kết quả ra màn hình

### Phân tích

- Văn bản (Unicode, có tiếng Việt) phải đổi sang byte bằng **UTF-8** trước khi mã hoá.

- Bản mã là byte nhị phân không in ra được, nên in dạng **Base64**.

- Tạo **IV ngẫu nhiên** mỗi lần, ghép `IV || Ciphertext` rồi mới Base64, để lúc giải mã tách IV ra được.

- Làm thêm chức năng **giải mã văn bản** (menu 5) để kiểm chứng kết quả.

### Các bước làm

**Bước 1.** Nhập văn bản, `Encoding.UTF8.GetBytes`.

**Bước 2.** `aes.Key = _key; aes.GenerateIV();`

**Bước 3.** `aes.EncryptCbc(plain, aes.IV, PaddingMode.PKCS7)` ra bản mã.

**Bước 4.** Ghép 16 byte IV + bản mã, `Convert.ToBase64String`, in ra màn hình.

**Bước 5.** Giải mã: Base64 sang byte, cắt 16 byte đầu làm IV, phần còn lại là bản mã, `DecryptCbc`, `UTF8.GetString`.


---

Mã hóa một đoạn văn bản ngắn 

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/712587aa-2f70-4016-aa10-b76d8b0f4eba" />


## Ý 5: Mã hoá một file và lưu vào một file

### Phân tích

- Để xử lý file **hàng GB**, tuyệt đối **không** đọc cả file vào bộ nhớ (`File.ReadAllBytes` bị giới hạn mảng khoảng 2 GB và tốn RAM).

- Dùng **xử lý theo luồng (stream)**: đọc từng khối 4 MB, mã hoá, ghi ra ngay. Bộ nhớ sử dụng gần như không đổi dù file nhỏ hay lớn.

- Dùng `CryptoStream` bọc quanh `FileStream` đích; `CopyTo` sẽ đẩy dữ liệu qua bộ mã hoá.

- Ghi 16 byte IV vào đầu file đích trước, rồi mới ghi dữ liệu mã hoá. Khi giải mã đọc 16 byte đầu làm IV.

### Các bước làm

**Bước 1.** Mở file nguồn (`FileMode.Open`) và file đích (`FileMode.Create`) với buffer 4 MB.

**Bước 2.** Ghi 16 byte IV vào file đích.

**Bước 3.** Tạo `CryptoStream(fout, aes.CreateEncryptor(), Write)`.

**Bước 4.** `fin.CopyTo(cs, 4MB)` rồi `cs.FlushFinalBlock()` để ghi khối padding cuối.

**Bước 5.** Giải mã: đọc 16 byte IV, tạo `CryptoStream(fin, aes.CreateDecryptor(), Read)`, `CopyTo(fout)`.


---
Tạo 2 file nguồn và file đích 

<img width="1902" height="1078" alt="image" src="https://github.com/user-attachments/assets/04f104d8-67e6-4655-8e57-5475e471728e" />


Thêm nội dung mã hóa vào file nguồn 

<img width="1912" height="1078" alt="image" src="https://github.com/user-attachments/assets/7236a0af-9b0c-4a8a-ba64-b66b33198137" />

Chọn file nguồn và đích để mã hóa 

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/67a296b2-fc32-4359-8d9a-81d118eb6f46" />

Mã hóa từ 1 file ghi ra 1 file 

<img width="1916" height="1078" alt="image" src="https://github.com/user-attachments/assets/79085bb9-e745-44be-94a3-d319db776579" />

## Yêu cầu thử nghiệm: file hàng GB, đo thời gian, so sánh byte, kết luận

### Phân tích

Yêu cầu gồm 4 việc:

- **Có file lớn:** không phải ai cũng sẵn file GB, nên chương trình tự **tạo file ngẫu nhiên** dung lượng tuỳ chọn (ví dụ 1024 MB = 1 GB, 2048 MB = 2 GB), ghi từng khối 1 MB.

- **Đo thời gian mã hoá và giải mã:** dùng `Stopwatch`, đo riêng từng giai đoạn, tính thêm **tốc độ MB/s = dung lượng / thời gian**.

- **So sánh từng byte file nguồn và file giải mã:** đọc song song 2 file theo khối 4 MB, so sánh bằng `Span.SequenceEqual`. Nếu khác, in ra vị trí byte lệch đầu tiên. Cách này không tốn RAM và chính xác tuyệt đối từng byte.

- **Kết luận từ số liệu:** chạy nhiều mức dung lượng (ví dụ 100 MB, 500 MB, 1 GB, 2 GB, 4 GB), ghi vào bảng và nhận xét.

### Các bước làm

**Bước 1.** Chọn menu, nhập dung lượng (MB).

**Bước 2.** Chương trình tự: tạo file, mã hoá, giải mã, so sánh byte, in báo cáo (kích thước, thời gian, MB/s, kết quả so sánh).

**Bước 3.** Lặp lại với các dung lượng khác nhau, điền bảng số liệu.




**Lưu ý dung lượng ổ đĩa:** mỗi lần thử cần khoảng **3 lần dung lượng file** (nguồn, mã hoá, giải mã). Thử 4 GB cần trống khoảng 12 GB. Cuối thử nghiệm chương trình hỏi có xoá file tạm không.

---

## Số liệu thử nghiệm và kết luận

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/73eb454b-5344-4988-b3c9-772d5990dbc2" />


### Kết luận

**1. Tính đúng đắn:** file giải mã **trùng khớp 100% từng byte** với file nguồn ở mọi dung lượng thử, kích thước bằng nhau, nên mã hoá rồi giải mã không làm mất hay sai dữ liệu.

**2. Thời gian tăng tuyến tính theo dung lượng:** dung lượng tăng khoảng 6,8 lần (300 MB lên 2048 MB) thì thời gian mã hoá tăng khoảng 4,8 lần và giải mã tăng khoảng 4,6 lần, tức tốc độ MB/s gần như ổn định. AES xử lý từng khối 16 byte độc lập về mặt chi phí, nên độ phức tạp là O(n) theo kích thước dữ liệu.

**3. Dung lượng bộ nhớ không đổi:** nhờ xử lý theo luồng 4 MB, file 2 GB hay 4 GB đều chạy không tốn thêm RAM đáng kể.

**4. Giải mã nhanh hơn mã hoá trong số liệu mẫu:** nguyên nhân là CBC khi **mã hoá** phải làm tuần tự (khối sau phụ thuộc khối mã hoá trước), còn khi **giải mã** các khối có thể xử lý song song. Ngoài ra tốc độ còn bị ảnh hưởng bởi cache ổ đĩa của hệ điều hành.

**5. Kích thước tăng không đáng kể:** bản mã chỉ lớn hơn bản gốc tối đa 32 byte, với file GB thì không đáng kể.

**6. Điểm nghẽn thường là ổ đĩa:** CPU hỗ trợ AES-NI mã hoá được hàng trăm MB/s đến hàng GB/s, nên với ổ HDD tốc độ tổng thể bị giới hạn bởi tốc độ đọc/ghi đĩa, không phải do thuật toán.

**7. Hạn chế cần biết:** CBC chỉ đảm bảo **bí mật**, không đảm bảo **toàn vẹn** (kẻ tấn công sửa bản mã mà không bị phát hiện). Thực tế nên dùng AES-GCM hoặc kết hợp HMAC. Bài này dùng CBC cho đơn giản và đúng nội dung bài tập.

---
