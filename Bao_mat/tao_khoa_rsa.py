from Crypto.PublicKey import RSA
import os

def tao_khoa(ten):
    # Tạo thư mục nếu chưa có
    os.makedirs("khoa_rsa", exist_ok=True)

    khoa = RSA.generate(1024)
    khoa_bi_mat = khoa.export_key()
    khoa_cong_khai = khoa.publickey().export_key()

    with open(f"khoa_rsa/khoa_bi_mat_{ten}.pem", "wb") as f:
        f.write(khoa_bi_mat)
    with open(f"khoa_rsa/khoa_cong_khai_{ten}.pem", "wb") as f:
        f.write(khoa_cong_khai)

# Tạo khóa cho cả người gửi và người nhận
tao_khoa("nguoi_gui")
tao_khoa("nguoi_nhan")

print("✅ Đã tạo xong các khóa RSA.")
