import json, base64, hashlib, zlib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Cipher import AES, PKCS1_OAEP
import os

# ====== HÀM HỖ TRỢ ======

def tai_khoa(duong_dan):
    with open(duong_dan, 'rb') as f:
        return RSA.import_key(f.read())

def kiem_tra_chu_ky(metadata: bytes, chu_ky_b64: str, khoa_cong_khai) -> bool:
    bam = SHA512.new(metadata)
    chu_ky = base64.b64decode(chu_ky_b64)
    try:
        pkcs1_15.new(khoa_cong_khai).verify(bam, chu_ky)
        return True
    except (ValueError, TypeError):
        return False

def giai_ma_khoa(khoa_ma_b64: str, khoa_bi_mat) -> bytes:
    try:
        giai_ma = PKCS1_OAEP.new(khoa_bi_mat)  # ✅ Đổi thuật toán giải mã
        khoa_ma = base64.b64decode(khoa_ma_b64)
        khoa_phien = giai_ma.decrypt(khoa_ma)
        return khoa_phien
    except Exception as e:
        print("[ERROR] Giải mã khóa phiên lỗi:", str(e))
        return None

def aes_giai_ma(nonce_b64: str, cipher_b64: str, tag_b64: str, khoa_phien: bytes) -> bytes:
    nonce = base64.b64decode(nonce_b64)
    cipher = base64.b64decode(cipher_b64)
    tag = base64.b64decode(tag_b64)
    aes = AES.new(khoa_phien, AES.MODE_GCM, nonce=nonce)
    return aes.decrypt_and_verify(cipher, tag)

def kiem_tra_hash(nonce_b64: str, cipher_b64: str, tag_b64: str, hash_du_kien: str) -> bool:
    du_lieu = base64.b64decode(nonce_b64) + base64.b64decode(cipher_b64) + base64.b64decode(tag_b64)
    hash_tinh_duoc = hashlib.sha512(du_lieu).hexdigest()
    return hash_tinh_duoc == hash_du_kien

# ====== BẮT ĐẦU XỬ LÝ ======

print("Người nhận: Ready!")  # Handshake

try:
    with open("goi_tin.json", "r") as f:
        goi_tin = json.load(f)
except Exception as e:
    print("NACK - Không thể đọc gói tin:", str(e))
    exit()

try:
    # Tải khóa
    khoa_cong_khai_gui = tai_khoa("khoa_rsa/khoa_cong_khai_nguoi_gui.pem")
    khoa_bi_mat_nhan = tai_khoa("khoa_rsa/khoa_bi_mat_nguoi_nhan.pem")

    # Tách các trường từ gói tin
    metadata_dict = goi_tin["metadata"]
    chu_ky = goi_tin["chu_ky"]
    khoa_phien_ma = goi_tin["khoa_phien_ma"]
    nonce_b64 = goi_tin["nonce"]
    du_lieu_ma_b64 = goi_tin["du_lieu_ma"]
    tag_b64 = goi_tin["tag"]
    bam_hex = goi_tin["hash"]

    # Ghép metadata dạng bytes
    metadata_bytes = f"{metadata_dict['tenfile']}|{metadata_dict['thoigian']}|{metadata_dict['loaifile']}".encode()

    # Kiểm tra chữ ký
    if not kiem_tra_chu_ky(metadata_bytes, chu_ky, khoa_cong_khai_gui):
        print("NACK - Sai chữ ký! Không xác minh được nguồn gốc dữ liệu.")
        exit()

    # Kiểm tra hash
    if not kiem_tra_hash(nonce_b64, du_lieu_ma_b64, tag_b64, bam_hex):
        print("NACK - Lỗi toàn vẹn dữ liệu (Hash không khớp).")
        exit()

    # Giải mã khóa phiên
    khoa_phien = giai_ma_khoa(khoa_phien_ma, khoa_bi_mat_nhan)
    if not khoa_phien:
        print("NACK - Giải mã khóa phiên thất bại!")
        exit()

    # Giải mã dữ liệu bằng AES-GCM
    try:
        du_lieu = aes_giai_ma(nonce_b64, du_lieu_ma_b64, tag_b64, khoa_phien)
    except Exception as e:
        print("NACK - Lỗi xác thực AES-GCM:", str(e))
        exit()

    # Giải nén zlib
    try:
        noi_dung = zlib.decompress(du_lieu)
    except Exception as e:
        print("NACK - Giải nén thất bại:", str(e))
        exit()
    print("✅ Nội dung sau giải nén:")
    print(noi_dung.decode(errors='ignore'))  # Giải mã và in nội dung (nếu có ký tự lỗi thì bỏ qua)

    # Ghi ra file
    with open("bao_cao_tai_chinh_giai_ma.txt", "wb") as f:
        f.write(noi_dung)

    print("ACK - File hợp lệ, đã lưu vào 'bao_cao_tai_chinh_giai_ma.txt'.")

except Exception as e:
    print("NACK - Lỗi không xác định:", str(e))
