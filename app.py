import os
import secrets
import time
import base64
import struct
import zlib
import hashlib
import sqlite3
import numpy as np
from io import BytesIO
from flask import Flask, request, render_template, flash, redirect, url_for, send_file
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ----------------------------------------
# App Configuration
# ----------------------------------------
app = Flask(__name__)
app.secret_key = "super_secure_key_2025"
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

TOKEN_TTL = 15 * 60  # Token valid for 15 minutes
DB_PATH = "tokens.db"

# ----------------------------------------
# Initialize token database
# ----------------------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL,
            used INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

def save_token(token):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO tokens (token, created_at, used) VALUES (?, ?, 0)",
              (token, int(time.time())))
    conn.commit()
    conn.close()

# ----------------------------------------
# Encryption Helpers
# ----------------------------------------
def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200_000)
    return kdf.derive(password.encode())

def encrypt_bytes(data, password):
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, data, None)
    return salt, nonce, ct

def bytes_to_bits(b):
    return np.unpackbits(np.frombuffer(b, dtype=np.uint8))

def bits_to_bytes(bits):
    pad = (-bits.size) % 8
    if pad:
        bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)])
    return np.packbits(bits).tobytes()

# ----------------------------------------
# Flask Routes
# ----------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encode', methods=['POST'])
def encode():
    cover = request.files.get('cover')
    secret = request.files.get('secret')

    if not cover or not secret:
        flash("Please upload both cover PNG and secret file.", "error")
        return redirect(url_for('index'))

    # Generate one-time token
    token = secrets.token_urlsafe(8)
    save_token(token)

    # Read secret and encrypt
    secret_bytes = secret.read()
    salt, nonce, ciphertext = encrypt_bytes(secret_bytes, token)
    encrypted_data = salt + nonce + ciphertext
    bits = bytes_to_bits(encrypted_data)

    # Load cover image
    img = Image.open(cover.stream).convert('RGB')
    arr = np.array(img)
    flat = arr.flatten()
    if bits.size > flat.size:
        flash("Cover image too small to hide secret data.", "error")
        return redirect(url_for('index'))

    flat[:bits.size] = (flat[:bits.size] & 0xFE) | bits
    stego_arr = flat.reshape(arr.shape)

    # Save stego image
    stego_filename = f"stego_{secrets.token_hex(6)}.png"
    stego_path = os.path.join(UPLOAD_FOLDER, stego_filename)
    Image.fromarray(stego_arr).save(stego_path)

    # Generate public download link (Render will host this)
    link = url_for('download_file', filename=stego_filename, _external=True)

    return render_template('result.html', token=token, link=link)

@app.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
