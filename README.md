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

# BÀI 2: MÃ HOÁ RSA, SHA-256, CHỮ KÝ SỐ

RSA là **mã hoá bất đối xứng**: có **cặp khoá**, mã hoá bằng khoá này thì chỉ giải mã được bằng khoá kia.

**Nguyên lý toán học tóm tắt:**

- Chọn 2 số nguyên tố lớn `p`, `q`; tính `n = p × q` (modulus) và `φ(n) = (p-1)(q-1)`.

- Chọn `e` nguyên tố cùng nhau với `φ(n)` (thường `e = 65537`, chỉ 17 bit); tính `d` sao cho `e × d ≡ 1 (mod φ(n))`.

- **Public key = (n, e)**, **Private key = (n, d)** (kèm p, q, dp, dq, qinv để tăng tốc).

- Mã hoá: `c = m^e mod n`. Giải mã: `m = c^d mod n`.

- Ký số là làm ngược lại: dùng khoá bí mật `d` để tạo chữ ký, ai có khoá công khai cũng kiểm tra được.

 RSA-OAEP với SHA-256 (an toàn hơn PKCS#1 v1.5). Với khoá 2048 bit (k = 256 byte), dữ liệu tối đa là:

```text
k - 2 × hLen - 2 = 256 - 2 × 32 - 2 = 190 byte
```


---

## Ý 1: Sinh cặp khoá

### Phân tích

- Dùng `RSA.Create(2048)`; thư viện tự chọn p, q nguyên tố ngẫu nhiên và tính n, e, d.

- 2048 bit là mức tối thiểu hiện nay được khuyến nghị; cho phép nhập 1024, 3072, 4096 để phục vụ ý 7 (so sánh tốc độ).

### Các bước làm

**Bước 1.** Nhập độ dài khoá (mặc định 2048).

**Bước 2.** `RSA.Create(bits)`.

---

Sinh cặp khóa 

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/3b33bbfa-7c39-4238-a77d-4971ea105fdb" />



## Ý 2: Xuất cặp khoá ra file PEM

### Phân tích

- **PEM** = dữ liệu nhị phân **DER** được mã hoá Base64, kẹp giữa dòng `-----BEGIN ...-----` và `-----END ...-----`.

- Public key xuất theo chuẩn **SubjectPublicKeyInfo** (X.509), header `BEGIN PUBLIC KEY`: `ExportSubjectPublicKeyInfoPem()`.

- Private key xuất theo chuẩn **PKCS#8**, header `BEGIN PRIVATE KEY`: `ExportPkcs8PrivateKeyPem()`.

### Các bước làm

**Bước 1.** Hỏi tên 2 file (mặc định `public.pem`, `private.pem`).

**Bước 2.** `File.WriteAllText(public.pem, rsa.ExportSubjectPublicKeyInfoPem())`.

**Bước 3.** `File.WriteAllText(private.pem, rsa.ExportPkcs8PrivateKeyPem())`.


---
Sinh file PEM khi có cặp khóa 

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/14d16009-98e0-4061-824c-1300843dd84c" />



##  Ý 3: Xem file PEM cùng ý nghĩa các byte trong định dạng PEM

### Phân tích

Một file PEM có 3 lớp:

**Lớp 1, văn bản:** dòng header, các dòng Base64 (64 ký tự/dòng), dòng footer.

**Lớp 2, DER:** bỏ header/footer, giải Base64 ra dữ liệu nhị phân. DER là mã hoá **ASN.1** theo bộ ba **Tag - Length - Value (TLV)**.

**Lớp 3, ý nghĩa các phần tử ASN.1:**

- Tag `30` = SEQUENCE (nhóm các phần tử con).

- Tag `02` = INTEGER (số nguyên lớn, big-endian; thêm byte `00` đứng đầu nếu bit cao là 1 để không bị hiểu là số âm).

- Tag `03` = BIT STRING (byte đầu cho biết số bit thừa, thường là `00`).

- Tag `04` = OCTET STRING (chuỗi byte; trong PKCS#8 chứa nguyên khoá RSA).

- Tag `05` = NULL (`05 00`).

- Tag `06` = OBJECT IDENTIFIER (mã định danh thuật toán).

- Length: nếu < 0x80 thì chính là độ dài; `81 XX` = độ dài 1 byte; `82 XX XX` = độ dài 2 byte.

**Cấu trúc byte của public key 2048 bit (294 byte):**

```text
30 82 01 22                      SEQUENCE, dài 0x0122 = 290 byte
   30 0D                         SEQUENCE (AlgorithmIdentifier), dài 13 byte
      06 09 2A 86 48 86 F7 0D 01 01 01    OID 1.2.840.113549.1.1.1 = rsaEncryption
      05 00                      NULL (không có tham số)
   03 82 01 0F 00                BIT STRING dài 0x010F = 271 byte, 00 = không thừa bit
      30 82 01 0A                SEQUENCE (RSAPublicKey), dài 266 byte
         02 82 01 01 00 <256 byte>   INTEGER n (modulus), 257 byte do có 00 đứng đầu
         02 03 01 00 01              INTEGER e = 0x010001 = 65537
```

**Cấu trúc private key (PKCS#8):**

```text
SEQUENCE
   INTEGER 0                     version
   SEQUENCE { OID rsaEncryption, NULL }
   OCTET STRING
      SEQUENCE (RSAPrivateKey - PKCS#1)
         INTEGER 0               version
         INTEGER n               modulus
         INTEGER e               public exponent
         INTEGER d               private exponent
         INTEGER p               nguyên tố thứ 1
         INTEGER q               nguyên tố thứ 2
         INTEGER dp = d mod (p-1)
         INTEGER dq = d mod (q-1)
         INTEGER qinv = q^-1 mod p
```

Các thành phần dp, dq, qinv phục vụ **định lý số dư Trung Hoa (CRT)** giúp giải mã nhanh gấp khoảng 3-4 lần.

### Các bước làm

**Bước 1.** Đọc file PEM, lấy dòng đầu làm header, loại bỏ các dòng `-----`, nối phần Base64 và giải mã ra mảng byte DER.

**Bước 2.** Viết hàm đệ quy `Dump()` đọc từng phần tử: byte tag, byte(s) length, rồi value.

**Bước 3.** Nếu là SEQUENCE thì gọi đệ quy vào bên trong; nếu là BIT STRING/OCTET STRING mà nội dung bắt đầu bằng `30` thì cũng đệ quy (vì bên trong là DER lồng nhau).

**Bước 4.** Với INTEGER in số bit và hex rút gọn; với OID giải mã sang dạng `1.2.840...`.

**Bước 5.** In chú giải ý nghĩa tag và length.

Xem file PEM

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/da6b87a3-9ca9-4077-b6d9-706aa02ebc18" />


---

## Ý 4: Nhập file PEM, lấy n, e (public) và n, e, d, ... (private)

### Phân tích

- `rsa.ImportFromPem(text)` tự nhận dạng các loại header (`PUBLIC KEY`, `PRIVATE KEY`, `RSA PRIVATE KEY`).

- Lấy tham số bằng `rsa.ExportParameters(false)` (chỉ phần công khai: `Modulus` = n, `Exponent` = e) hoặc `ExportParameters(true)` (đầy đủ: thêm `D`, `P`, `Q`, `DP`, `DQ`, `InverseQ`).

- Kiểm chứng: `p × q == n` bằng `BigInteger`.

### Các bước làm

**Bước 1.** Nút «Mở file PEM...» chọn `public.pem`: gọi `ImportFromPem`, `ExportParameters(false)`, hiện n, e (hex và thập phân) ở tab «Tham số khoá».

**Bước 2.** Mở `private.pem`: gọi `ExportParameters(true)`, hiện n, e, d, p, q, dp, dq, qinv.

**Bước 3.** Kiểm tra `p × q = n`.

Tham số khóa n và e

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/d0a2e5aa-045e-48cf-8151-8430b4002464" />

Tham số khóa d p q

<img width="1916" height="1078" alt="image" src="https://github.com/user-attachments/assets/f0f5d60f-0d53-4eef-8a40-785da7170902" />


---

## Ý 5: Mã hoá dữ liệu bằng key vừa import (tối đa 190 byte, lưu Base64)

### Phân tích

- Nhập public key từ PEM (dùng lại hàm ý 4), mã hoá mảng byte ≤ 190 byte bằng `rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256)`.

- Dữ liệu đầu vào cho phép 3 cách: gõ văn bản; **sinh khoá AES-256 ngẫu nhiên (32 byte)** đúng như gợi ý đề bài; đọc file nhị phân nhỏ.

- Nếu dữ liệu > 190 byte thì báo lỗi rõ ràng (vì vượt giới hạn OAEP).

- Bản mã luôn dài **256 byte** (bằng độ dài n) bất kể dữ liệu ngắn hay dài; ghi ra file dạng Base64 (344 ký tự).

- Để bước 6 đối chiếu được, chương trình lưu thêm dữ liệu gốc (Base64) vào file `cipher.b64.plain`.

### Các bước làm

**Bước 1.** Nhập đường dẫn `public.pem`, nạp khoá.

**Bước 2.** Chọn nguồn dữ liệu, tạo mảng byte, kiểm tra `Length <= 190`.

**Bước 3.** `rsa.Encrypt(...)`.

**Bước 4.** `Convert.ToBase64String` và lưu `cipher.b64`; lưu thêm bản gốc `cipher.b64.plain`.



---

Mã hóa dữ liệu 

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/6d039b71-2696-495a-b10b-16038e0e696c" />



## Ý 6: Giải mã, so sánh với nguồn trước khi mã hoá

### Phân tích

- Đầu vào: file PEM private key và file chứa bản mã Base64.

- Quy trình: đọc Base64 sang byte, `rsa.Decrypt(cipher, OaepSHA256)` bằng private key.

- So sánh kết quả với dữ liệu gốc bằng `SequenceEqual` (so từng byte).

### Các bước làm

**Bước 1.** Nhập `private.pem` và `cipher.b64`.

**Bước 2.** Giải mã, in kích thước và Base64 của kết quả.

**Bước 3.** Đọc `cipher.b64.plain`, so sánh từng byte và in "GIỐNG HỆT" hoặc "KHÁC NHAU".

Giải mã dữ liệu

<img width="1912" height="1078" alt="image" src="https://github.com/user-attachments/assets/6c26b568-3bb7-41cd-be1d-b173bec75b77" />


---

## Ý 7: Đánh giá tốc độ mã hoá/giải mã, khoá public (n, e bé) so với private (n, d lớn)

### Phân tích

- Về lý thuyết: mã hoá `m^e mod n` với `e = 65537` (17 bit) chỉ cần khoảng 17 phép bình phương + 2 phép nhân; còn giải mã `c^d mod n` với `d` cỡ 2048 bit cần khoảng **2048 phép bình phương** modulo n, nên chậm hơn rất nhiều.

- Đo ở **2 mức** để quan sát rõ:

**Mức A, dùng API .NET:** đo `Encrypt` (public) và `Decrypt` (private) với các độ dài khoá 1024, 2048, 3072, 4096. Lưu ý .NET dùng CRT khi giải mã nên chênh lệch được rút ngắn.



**Mức B, RSA thuần bằng `BigInteger.ModPow` không CRT:** đo `m^e mod n` và `c^d mod n` trực tiếp để thấy đúng bản chất "e nhỏ, d to".

- Mỗi phép đo lặp nhiều lần (mặc định 300) rồi lấy **trung bình** để giảm nhiễu; có bước khởi động (warm-up) trước.

- Kết luận kỳ vọng: **khoá công khai (e bé) nhanh hơn nhiều lần khoá bí mật (d lớn)**; khoá càng dài thì phép dùng khoá bí mật càng chậm (xấp xỉ tỉ lệ luỹ thừa 3 theo số bit).

### Các bước làm

**Bước 1.** Với mỗi độ dài khoá, sinh khoá mới, tạo dữ liệu 32 byte.

**Bước 2.** `Stopwatch` đo vòng lặp `Encrypt`, rồi vòng lặp `Decrypt`; chia cho số lần lặp.

**Bước 3.** Lấy `Modulus`, `Exponent`, `D` bằng `ExportParameters(true)`, đổi sang `BigInteger`, đo `ModPow(m, e, n)` và `ModPow(c, d, n)`; kiểm tra giải ra đúng `m`.

**Bước 4.** In bảng thời gian, số bit của e và d, tỉ lệ chậm.

Dùng API.NET và RSA thuần bằng `BigInteger.ModPow để đánh giá 

<img width="1916" height="1078" alt="image" src="https://github.com/user-attachments/assets/38119571-2fa2-4599-9afd-6fe5c8145950" />


---

## Ý 8: Giao diện sinh chuỗi băm SHA-256, đánh giá sự thay đổi khi đầu vào thay đổi rất ít

### Phân tích

- SHA-256 biến dữ liệu bất kỳ thành giá trị băm **256 bit (32 byte, 64 ký tự hex)**.

- Tính chất cần chứng minh là **hiệu ứng tuyết lở (avalanche effect)**: đầu vào đổi 1 bit thì khoảng **một nửa số bit** của kết quả đổi (kỳ vọng khoảng 128/256 bit; độ lệch chuẩn khoảng 8 bit nên thường rơi vào khoảng 110-146).

- Cách đo: đếm số bit khác nhau giữa 2 chuỗi băm bằng `popcount(h1 XOR h2)`.

- Giao diện có 3 chức năng: nhập 2 chuỗi tuỳ ý để so sánh; nút «Chuỗi 2 = chuỗi 1 lật đúng 1 bit»; nút «Băm một file...». Thêm nút thống kê: lật lần lượt **từng bit** của chuỗi gốc, tính trung bình, nhỏ nhất, lớn nhất số bit khác.

- Giao diện gồm 2 ô nhập, 2 ô hiển thị chuỗi băm, và một **bản đồ 16×16 = 256 ô** tương ứng 256 bit của chuỗi băm: **ô xanh = bit thay đổi**, ô xám = bit giữ nguyên. Gõ đến đâu kết quả cập nhật ngay đến đó.

### Các bước làm

**Bước 1.** Nhận chuỗi 1, đổi sang byte UTF-8.

**Bước 2.** Tạo chuỗi 2 (nhập tay hoặc lật 1 bit `byte[0] ^= 0x01`).

**Bước 3.** `SHA256.HashData` cho cả hai, in hex.

**Bước 4.** Đếm bit khác nhau của đầu vào và của kết quả, in tỉ lệ phần trăm.

**Bước 5.** Chạy thống kê lật từng bit, in trung bình/min/max.

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/56d4bf9f-e378-411a-96e8-7083323a924b" />
<img width="1912" height="1078" alt="image" src="https://github.com/user-attachments/assets/1e9e22dc-21c4-4084-81dc-daa53489b33f" />

Băm từ 1 file 

<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/f481bb91-543f-4e72-826b-bddf659f90a8" />


"Hello World" và "Hello World!" cho 2 chuỗi băm khác nhau 123/256 bit (48,0%). Lật từng bit của "Hello World" (88 lần): trung bình 127,0 bit khác, nhỏ nhất 103, lớn nhất 147, đúng kỳ vọng khoảng 50%. 

**Kết luận:** thay đổi nhỏ nhất ở đầu vào làm kết quả băm thay đổi hoàn toàn và không thể dự đoán, nên không thể suy ra mối liên hệ giữa 2 giá trị băm.

---

## Ý 9: Chữ ký số, đề xuất phương pháp để cùng dữ liệu, cùng người ký vẫn cho chữ ký khác nhau ở mỗi lần ký

### Phân tích

**Chữ ký số cơ bản:**

```text
Ký:        S = (Pad(Hash(M)))^d mod n      (dùng khoá bí mật)
Kiểm tra:  Pad(Hash(M)) == S^e mod n       (dùng khoá công khai)
```

- Dữ liệu khác nhau thì băm khác nhau nên chữ ký khác nhau (đúng như đề nói).

**Vì sao cùng dữ liệu, cùng khoá lại ra cùng chữ ký?** 

Vì chữ ký truyền thống **RSASSA-PKCS1-v1_5** là **tất định (deterministic)**: không có yếu tố ngẫu nhiên nào, toàn bộ phép tính chỉ phụ thuộc `M` và `d`. Giao diện chứng minh điều này ở mục «Chữ ký số»: ký 3 lần theo PKCS#1 v1.5 ra 3 chữ ký giống hệt nhau (hàng tô đỏ).

**Mong muốn:** cùng `M`, cùng private key mà mỗi lần ký một khác, **nhưng bên nhận vẫn kiểm tra đúng**.

**Nguyên tắc giải quyết:** đưa **một giá trị ngẫu nhiên** vào quá trình ký, và bảo đảm bên kiểm tra khôi phục hoặc nhận được giá trị đó để verify.

**Đề xuất 1 (khuyến nghị): RSASSA-PSS (Probabilistic Signature Scheme, RFC 8017)**

- Mỗi lần ký sinh **salt ngẫu nhiên** (32 byte).

- Tính `H' = Hash(00×8 || Hash(M) || salt)`, rồi mã hoá salt vào khối EM bằng hàm mặt nạ MGF1, sau đó mới luỹ thừa bằng `d`.

- Salt được **nhúng sẵn trong chữ ký**; bên kiểm tra tự khôi phục salt từ chữ ký bằng khoá công khai nên **không phải truyền thêm gì**.

- Là chuẩn quốc tế, có chứng minh an toàn, .NET hỗ trợ sẵn: `SignData(data, SHA256, RSASignaturePadding.Pss)`.

**Đề xuất 2: thêm nonce vào dữ liệu trước khi băm**

- Mỗi lần ký sinh `nonce` ngẫu nhiên 16 byte; ký `Hash(M || nonce)` bằng private key.

- Gói chữ ký gửi đi: `nonce || signature`.

- Bên kiểm tra tách nonce, tự băm `M || nonce`, rồi verify chữ ký.

- Ưu điểm: dễ hiểu, tự cài được trên mọi nền tảng. Nhược điểm: tự thiết kế giao thức nên cần cẩn thận, nonce phải truyền kèm.


**So sánh:**

| Phương pháp | Chữ ký mỗi lần khác nhau | Cần truyền thêm dữ liệu | Chuẩn hoá | Khuyến nghị |
|---|---|---|---|---|
| PKCS#1 v1.5 | Không (tất định) | Không | Có | Chỉ để đối chứng |
| PSS (salt ngẫu nhiên) | Có | Không (salt nằm trong chữ ký) | Có (RFC 8017) | Nên dùng |
| Nonce tự thiết kế | Có | Có (nonce) | Không | Chỉ minh hoạ |

**Lưu ý:** khi chữ ký có tính ngẫu nhiên thì không thể so sánh hai chữ ký để biết "cùng dữ liệu" hay không; cách đúng luôn là **hàm verify** (kiểm tra bằng public key), không so sánh chuỗi chữ ký.

### Các bước làm

**Bước 1.** Nhập `private.pem`, `public.pem` và dữ liệu cần ký.

**Bước 2.** Phần (0): ký 3 lần bằng `RSASignaturePadding.Pkcs1`, in 3 chữ ký, kết luận giống hệt nhau.

**Bước 3.** Phần (A): ký 3 lần bằng `RSASignaturePadding.Pss`; in 3 chữ ký khác nhau và `VerifyData = True` cho cả ba.

**Bước 4.** Phần (B): mỗi lần sinh nonce, tính `SHA256(data || nonce)`, `SignHash`, gói `nonce || sig`; bên nhận tách gói, tự băm, `VerifyHash`.

**Bước 5.** Chống giả mạo: sửa dữ liệu thêm 1 ký tự rồi verify chữ ký cũ phải trả về `False`.



<img width="1917" height="1078" alt="image" src="https://github.com/user-attachments/assets/915361d1-b04d-4015-b9ee-7f8132aedf1b" />



### Kết luận 

**1.** Phép dùng **khoá công khai (e = 65537, chỉ 17 bit)** nhanh hơn rất nhiều so với phép dùng **khoá bí mật (d cỡ 1000-4000 bit)**: ở khoá 2048 bit, giải mã chậm hơn mã hoá khoảng 20 lần với API có CRT và trên 100 lần với RSA thuần không CRT.

**2.** Nguyên nhân: số phép bình phương modulo của luỹ thừa nhanh tỉ lệ thuận với **số bit của số mũ**; e có 17 bit còn d có khoảng 2048 bit.

**3.** Khoá càng dài (1024 sang 3072) thì thời gian mã hoá tăng ít, còn thời gian giải mã tăng rất mạnh, xấp xỉ luỹ thừa 3 theo độ dài khoá.

**4.** CRT (dùng p, q, dp, dq, qinv có trong private key) giúp giải mã nhanh hơn khoảng 3-4 lần so với tính `c^d mod n` trực tiếp, lý do thư viện lưu các tham số này.

**5.** Hệ quả thực tế: do RSA chậm và bị giới hạn kích thước dữ liệu (190 byte), người ta chỉ dùng RSA để mã hoá **khoá phiên AES** hoặc **ký giá trị băm**, còn dữ liệu lớn dùng AES (nhanh hơn RSA hàng nghìn lần, như số liệu bài 1 là hàng trăm MB/s).

**6.** Vì ký số dùng khoá bí mật nên **ký chậm, kiểm tra chữ ký nhanh**, hợp lý vì một người ký nhưng nhiều người kiểm tra.
