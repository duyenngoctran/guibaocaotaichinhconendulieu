
# 💬 ỨNG DỤNG NHẮN TIN BẢO MẬT (ALICE ↔ BOB)

Ứng dụng này mô phỏng hệ thống nhắn tin bảo mật giữa 2 người dùng (Alice và Bob), sử dụng **mã hóa RSA + AES**, **chữ ký số**, **hash SHA-256**, và giao diện người dùng hiện đại bằng `customtkinter`.

---

## 🧩 Tính năng chính

| Tính năng                  | Mô tả |
|---------------------------|-------|
| 🔐 Mã hóa kết hợp          | Sử dụng RSA để trao đổi khóa AES, và AES-CBC để mã hóa nội dung |
| ✍️ Chữ ký số               | Tin nhắn được ký bằng RSA + SHA-256 |
| 🔑 Quản lý khóa tự động    | Tự tạo hoặc tải khóa RSA từ thư mục `keys/` |
| 📄 Gửi file/ảnh            | Hỗ trợ gửi tệp nhị phân như ảnh và hiển thị ảnh thu nhỏ |
| 😊 Emoji hỗ trợ            | Hộp chọn emoji khi gửi tin |
| 💬 Giao diện trực quan     | Sử dụng `customtkinter` cho UI đẹp, có chế độ sáng/tối |
| 📜 Giao thức đơn giản      | Truyền dữ liệu qua TCP Socket, định dạng JSON |

---

## 🛠️ Kiến trúc thư mục

```
📁 project/
├── client.py             # Giao diện người gửi (Alice)
├── config.py             # Cấu hình host, port, thư mục khóa
├── crypto_utils.py       # Hàm hỗ trợ mã hóa/giải mã
├── keys/                 # Thư mục chứa khóa RSA
│   ├── alice_private.pem
│   ├── alice_public.pem
│   ├── bob_private.pem
│   └── bob_public.pem
```

---

## 📦 Cài đặt

```bash
pip install customtkinter pycryptodome pillow
```

---

## ▶️ Chạy ứng dụng

```bash
python client.py
```

- Giao diện sẽ mở ra cửa sổ **Alice Chat**
- Sau khi kết nối đến Bob, có thể:
  - Gửi tin nhắn văn bản
  - Gửi emoji
  - Gửi ảnh hoặc tệp nhị phân (ảnh sẽ được hiển thị thu nhỏ)

---

## 🔐 Chi tiết bảo mật

| Cơ chế | Công nghệ |
|--------|-----------|
| Mã hóa khóa phiên (AES) | RSA 2048-bit (PKCS#1 OAEP) |
| Mã hóa nội dung | AES-256-CBC |
| Chữ ký số | RSA + SHA-256 |
| Băm nội dung | SHA-256 |
| Kiểm tra chữ ký | Trước khi chấp nhận tin nhắn |

---

## 📋 Ghi chú

- Bạn cần chạy `server.py` tương ứng (chưa kèm ở đây) để mô phỏng người nhận (Bob)
- Đây là bản **demo học thuật** cho bài tập lớn hoặc đồ án liên quan đến **mật mã học**, **bảo mật mạng**, hoặc **ứng dụng client-server bảo mật**

---

> 🚀 Tác giả: Sinh viên Đại học Duy Tân / Đại Nam  
> ✨ Phù hợp cho đồ án "Ứng dụng truyền tin bảo mật sử dụng mã hóa lai RSA-AES"
