import json, time, zlib, base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

def doc_file(tenfile):
    with open(tenfile, "rb") as f:
        return f.read()

def nen_du_lieu(data):
    return zlib.compress(data)

def ky_du_lieu(metadata_bytes, private_key):
    h = SHA512.new(metadata_bytes)
    signature = pkcs1_15.new(private_key).sign(h)
    return base64.b64encode(signature).decode()



# B1: Metadata
ten_file = "finance.txt"
loai_file = "text/plain"
timestamp = str(int(time.time()))
metadata = f"{ten_file}|{timestamp}|{loai_file}".encode()

# B2: Load keys
khoa_bi_mat_nguoi_gui = RSA.import_key(open("khoa_rsa/khoa_bi_mat_nguoi_gui.pem", "rb").read())
khoa_cong_khai_nguoi_nhan = RSA.import_key(open("khoa_rsa/khoa_cong_khai_nguoi_nhan.pem", "rb").read())

# B3: Ký metadata
chu_ky_b64 = ky_du_lieu(metadata, khoa_bi_mat_nguoi_gui)

# B4: Tạo khóa phiên
session_key = get_random_bytes(32)  # AES-256
nonce = get_random_bytes(12)

# B5: Nén + Mã hóa AES-GCM
du_lieu = nen_du_lieu(doc_file(ten_file))
cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(du_lieu)

# B6: Tính hash
hash_input = nonce + ciphertext + tag
hash_hex = SHA512.new(hash_input).hexdigest()

# B7: Mã hóa session_key bằng RSA
cipher_rsa = PKCS1_OAEP.new(khoa_cong_khai_nguoi_nhan)
session_key_ma_b64 = base64.b64encode(cipher_rsa.encrypt(session_key)).decode()

# B8: Tạo gói tin
packet = {
    "metadata": {
        "tenfile": ten_file,
        "thoigian": timestamp,
        "loaifile": loai_file
    },
    "chu_ky": chu_ky_b64,
    "khoa_phien_ma": session_key_ma_b64,
    "nonce": base64.b64encode(nonce).decode(),
    "du_lieu_ma": base64.b64encode(ciphertext).decode(),
    "tag": base64.b64encode(tag).decode(),
    "hash": hash_hex
}

with open("goi_tin.json", "w") as f:
    json.dump(packet, f, indent=4)

print("✅ Đã gửi gói tin vào 'goi_tin.json'")