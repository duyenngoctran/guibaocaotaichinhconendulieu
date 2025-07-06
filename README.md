# 📑 ỨNG DỤNG GỬI BÁO CÁO TÀI CHÍNH CÓ NÉN DỮ LIỆU

Ứng dụng này mô phỏng **hệ thống gửi nhận báo cáo tài chính** (như báo cáo quý, năm) giữa người gửi và người nhận, với các bước nén, mã hóa, ký số, kiểm tra toàn vẹn trước khi giải nén, nhằm đảm bảo tính bảo mật, giảm dung lượng khi truyền.

---

## 🧩 Mục đích chính

✅ Gửi báo cáo tài chính qua kênh không an toàn (email, USB, mạng) nhưng vẫn bảo mật.  
✅ Chứng minh được báo cáo đến từ đúng người gửi (chữ ký số).  
✅ Đảm bảo nội dung không bị chỉnh sửa (hash + xác minh chữ ký).  
✅ Giảm dung lượng bằng nén zlib.

---

## 🛠️ Kiến trúc thư mục

```
project/
├── nguoi_gui.py                 # Script gửi báo cáo: nén, ký, mã hóa, tạo goi_tin.json
├── nguoi_nhan.py                # Script nhận báo cáo: giải mã, kiểm tra, giải nén, lưu báo cáo
├── tao_khoa_rsa.py              # Tạo cặp khóa RSA cho người gửi & người nhận
├── finance.txt                  # Báo cáo tài chính gốc cần gửi
├── bao_cao_tai_chinh_giai_ma.txt # Báo cáo sau khi người nhận giải mã, giải nén
├── goi_tin.json                 # Gói tin chứa metadata, dữ liệu nén + mã hóa, chữ ký, hash
└── khoa_rsa/                    # Thư mục chứa các khóa RSA
    ├── khoa_bi_mat_nguoi_gui.pem
    ├── khoa_cong_khai_nguoi_gui.pem
    ├── khoa_bi_mat_nguoi_nhan.pem
    └── khoa_cong_khai_nguoi_nhan.pem
```

---

## ▶️ Hướng dẫn chạy

### 1️⃣ Tạo khóa RSA:
```bash
python tao_khoa_rsa.py
```

### 2️⃣ Gửi báo cáo:
- Đặt báo cáo cần gửi (ví dụ: `finance.txt`) cùng thư mục.
- Chạy script:
  ```bash
  python nguoi_gui.py
  ```
- Kết quả: tạo file `goi_tin.json`.

### 3️⃣ Nhận báo cáo:
```bash
python nguoi_nhan.py
```
- Nếu hợp lệ: báo cáo được giải nén, in ra màn hình & lưu vào `bao_cao_tai_chinh_giai_ma.txt`.

---

## 🔐 Cơ chế bảo mật

| Thành phần       | Mô tả                                     |
| ---------------- | ----------------------------------------- |
| **Nén báo cáo**  | zlib nén dữ liệu trước khi mã hóa         |
| **Mã hóa dữ liệu** | AES-256-GCM                              |
| **Mã hóa khóa phiên** | RSA 1024-bit (PKCS#1 OAEP)            |
| **Chữ ký số**    | RSA + SHA-512                            |
| **Hash kiểm tra** | SHA-512 của (nonce + ciphertext + tag)   |

---

## 📋 Ý nghĩa

✔️ Ứng dụng chứng minh kiến thức về nén dữ liệu, mật mã lai RSA-AES, chữ ký số.  
✔️ Phù hợp cho đồ án môn Bảo mật, An toàn thông tin, hoặc các bài tập lớn liên quan đến bảo vệ dữ liệu tài chính.

---

🚀 **Tác giả:** Sinh viên Đại học Duy Tân / Đại Nam  
✨ **Đề tài:** "Ứng dụng gửi báo cáo tài chính có nén dữ liệu và bảo mật"
