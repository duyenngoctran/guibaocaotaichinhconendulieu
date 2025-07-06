from flask import Flask, request, render_template, redirect, url_for, flash
import base64, hashlib, json, os, zlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

app = Flask(__name__)
app.secret_key = 's3cret'
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Tạm lưu gói tin
GOI_TIN_PATH = os.path.join(UPLOAD_FOLDER, "goi_tin.json")

@app.route("/")
def index():
    return render_template("nhan.html")

@app.route("/upload", methods=["POST"])
def upload_packet():
    packet = request.get_json()
    with open(GOI_TIN_PATH, "w") as f:
        json.dump(packet, f)
    return "✅ Đã nhận gói tin thành công!"

@app.route("/giai_ma", methods=["POST"])
def giai_ma():
    file = request.files["khoa"]
    khoa_data = file.read()

    try:
        khoa_bi_mat = RSA.import_key(khoa_data)
    except:
        return "❌ Lỗi: Không thể đọc khóa bí mật!"

    try:
        with open(GOI_TIN_PATH, "r") as f:
            goi_tin = json.load(f)
    except:
        return "❌ Chưa nhận được gói tin nào!"

    try:
        # B1: Metadata
        metadata = goi_tin["metadata"]
        chu_ky = goi_tin["chu_ky"]
        nonce_b64 = goi_tin["nonce"]
        cipher_b64 = goi_tin["du_lieu_ma"]
        tag_b64 = goi_tin["tag"]
        khoa_phien_ma = goi_tin["khoa_phien_ma"]
        bam_hex = goi_tin["hash"]

        # B2: Ghép metadata bytes
        metadata_bytes = f"{metadata['tenfile']}|{metadata['thoigian']}|{metadata['loaifile']}".encode()

        # B3: Giải mã khóa phiên
        khoa_ma = base64.b64decode(khoa_phien_ma)
        khoa_phien = PKCS1_OAEP.new(khoa_bi_mat).decrypt(khoa_ma)

        # B4: AES-GCM giải mã
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(cipher_b64)
        tag = base64.b64decode(tag_b64)
        aes = AES.new(khoa_phien, AES.MODE_GCM, nonce=nonce)
        du_lieu = aes.decrypt_and_verify(ciphertext, tag)

        # B5: Kiểm tra hash
        hash_input = nonce + ciphertext + tag
        hash_check = hashlib.sha512(hash_input).hexdigest()
        if hash_check != bam_hex:
            return "❌ Dữ liệu không toàn vẹn!"

        # B6: Giải nén
        noi_dung = zlib.decompress(du_lieu).decode(errors="ignore")

        # Ghi ra file
        save_path = os.path.join(UPLOAD_FOLDER, "giai_ma.txt")
        with open(save_path, "w", encoding="utf-8") as f:
            f.write(noi_dung)

        return f"✅ Đã giải mã thành công. Nội dung:<br><pre>{noi_dung}</pre>"

    except Exception as e:
        return f"❌ Lỗi khi giải mã: {str(e)}"

if __name__ == '__main__':
    app.run(port=5001, debug=True)
