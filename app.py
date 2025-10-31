import os
import secrets
import base64
import time
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Flask app setup
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Encryption helpers
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000
    )
    return kdf.derive(password.encode())

def encrypt_file(file_bytes: bytes, password: str):
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, file_bytes, None)
    return salt, nonce, ciphertext

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    secret = request.files.get('secret_file')
    cover = request.files.get('cover_image')

    if not secret or not cover:
        flash("Please upload both the secret file and cover image.", "error")
        return redirect(url_for('index'))

    # Generate one-time token
    token = secrets.token_urlsafe(12)

    # Read secret file
    secret_bytes = secret.read()
    salt, nonce, ciphertext = encrypt_file(secret_bytes, token)

    encrypted_blob = salt + nonce + ciphertext

    # Save encrypted file
    filename = f"encrypted_{secure_filename(secret.filename)}.bin"
    filepath = os.path.join(UPLOAD_DIR, filename)
    with open(filepath, 'wb') as f:
        f.write(encrypted_blob)

    # Create sharable link (Render or local)
    sharable_link = url_for('serve_file', filename=filename, _external=True)

    return render_template(
        'result.html',
        token=token,
        link=sharable_link
    )

@app.route('/file/<path:filename>')
def serve_file(filename):
    filepath = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(filepath):
        return f"This is the encrypted file link: {request.url}"
    else:
        return "File not found.", 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
