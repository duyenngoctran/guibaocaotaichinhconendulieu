from flask import Flask, request, render_template
import requests, os, time, zlib, base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

NGUOI_NHAN_URL = "http://localhost:5001/upload"  # Địa chỉ web người nhận

# Lấy đường dẫn tuyệt đối của file đang chạy
basedir = os.path.abspath(os.path.dirname(__file__))

@app.route("/")
def index():
    return render_template("gui.html")

@app.route("/send", methods=["POST"])
def send():
    file = request.files['file']
    ten_file = file.filename
    du_lieu = zlib.compress(file.read())

    # Metadata
    timestamp = str(int(time.time()))
    loai_file = "text/plain"
    metadata = f"{ten_file}|{timestamp}|{loai_file}".encode()

    # Đọc khóa từ đường dẫn tuyệt đối
    path_private_key = os.path.join(basedir, "..", "khoa_rsa", "khoa_bi_mat_nguoi_gui.pem")
    path_public_key = os.path.join(basedir, "..", "khoa_rsa", "khoa_cong_khai_nguoi_nhan.pem")

    khoa_bi_mat_gui = RSA.import_key(open(path_private_key, "rb").read())
    khoa_cong_khai_nhan = RSA.import_key(open(path_public_key, "rb").read())

    # Ký metadata
    chu_ky = pkcs1_15.new(khoa_bi_mat_gui).sign(SHA512.new(metadata))
    chu_ky_b64 = base64.b64encode(chu_ky).decode()

    # Mã hóa bằng AES-GCM
    session_key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(du_lieu)

    # Tính hash để kiểm tra toàn vẹn
    hash_input = nonce + ciphertext + tag
    bam_hex = SHA512.new(hash_input).hexdigest()

    # Mã hóa khóa phiên bằng RSA
    cipher_rsa = PKCS1_OAEP.new(khoa_cong_khai_nhan)
    session_key_ma = base64.b64encode(cipher_rsa.encrypt(session_key)).decode()

    # Gói tin
    packet = {
        "metadata": {
            "tenfile": ten_file,
            "thoigian": timestamp,
            "loaifile": loai_file
        },
        "chu_ky": chu_ky_b64,
        "khoa_phien_ma": session_key_ma,
        "nonce": base64.b64encode(nonce).decode(),
        "du_lieu_ma": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
        "hash": bam_hex
    }

    # Gửi tới người nhận
    try:
        res = requests.post(NGUOI_NHAN_URL, json=packet)
        return f"<h3>✅ Gửi thành công: {ten_file}</h3><p>Phản hồi từ người nhận: {res.text}</p>"
    except Exception as e:
        return f"<h3>❌ Lỗi gửi gói tin: {str(e)}</h3>"

if __name__ == '__main__':
    app.run(port=5000, debug=True)
