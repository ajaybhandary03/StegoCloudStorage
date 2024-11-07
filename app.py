import logging
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import numpy as np
from PIL import Image
import os
from functools import wraps

# Set up logging for debugging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['SECRET_KEY'] = Fernet.generate_key()

# Ensure necessary directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_files'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'stego_keys'), exist_ok=True)

# Utility to generate and save a unique key for each user
def generate_user_key(username):
    key = Fernet.generate_key()
    key_path = os.path.join(app.config['UPLOAD_FOLDER'], 'stego_keys', f"{username}_key.key")
    with open(key_path, "wb") as key_file:
        key_file.write(key)
    logging.debug(f"Generated and saved key for {username} at {key_path}")
    return key

def load_user_key(username):
    key_path = os.path.join(app.config['UPLOAD_FOLDER'], 'stego_keys', f"{username}_key.key")
    if os.path.exists(key_path):
        with open(key_path, "rb") as key_file:
            key = key_file.read()
        logging.debug(f"Loaded key for {username} from {key_path}")
        return key
    logging.warning(f"No key found for {username}")
    return None

# Embeds a unique key in a stego-image for each user
def create_stego_key_image(username):
    user_key = generate_user_key(username)
    cover_image = Image.new("RGB", (300, 300), color=(255, 255, 255))  # Blank cover image
    pixels = np.array(cover_image)
    binary_key = ''.join(format(byte, '08b') for byte in user_key)

    index = 0
    for x in range(pixels.shape[0]):
        for y in range(pixels.shape[1]):
            if index < len(binary_key):
                r, g, b = pixels[x, y]
                r = int(bin(r)[:-1] + binary_key[index], 2)
                pixels[x, y] = (r, g, b)
                index += 1

    stego_image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'stego_keys', f"{username}_stego.png")
    stego_image = Image.fromarray(pixels)
    stego_image.save(stego_image_path)
    logging.debug(f"Stego image saved for {username} at {stego_image_path}")
    return stego_image_path

# Key-based authentication decorator
def key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Route for login page
@app.route('/')
def login():
    return render_template('login.html')

# Route to handle login with stego-image
@app.route('/login', methods=['POST'])
def login_user():
    file = request.files.get('stego_key')
    if file:
        uploaded_key = extract_key_from_stego(file)
        user_key = load_user_key("user")

        if uploaded_key == user_key:
            session['logged_in'] = True
            flash("Login successful.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Failed to authenticate with provided key.", "danger")
    else:
        flash("No stego-image provided.", "danger")
    return redirect(url_for('login'))

# Extracts the key from a stego-image
def extract_key_from_stego(stego_image):
    image = Image.open(stego_image).convert("RGB")
    pixels = np.array(image)

    original_key = load_user_key("user")
    if original_key is None:
        raise ValueError("No key found for user")

    key_length_bits = len(original_key) * 8
    binary_key = ""
    index = 0

    for x in range(pixels.shape[0]):
        for y in range(pixels.shape[1]):
            if index < key_length_bits:
                r, g, b = pixels[x, y]
                binary_key += bin(r)[-1]
                index += 1
            if index >= key_length_bits:
                break
        if index >= key_length_bits:
            break

    key_bytes = bytes(int(binary_key[i:i+8], 2) for i in range(0, key_length_bits, 8))
    logging.debug("Extracted key from stego-image.")
    return key_bytes

# Dashboard page after successful login
@app.route('/dashboard')
@key_required
def dashboard():
    return render_template('dashboard.html')

# Route to handle file upload and hide encrypted data in a stego-image
@app.route('/upload', methods=['POST'])
@key_required
def upload_file():
    file = request.files.get('file')
    if file:
        filename = secure_filename(file.filename)
        user_key = load_user_key("user")
        if user_key is None:
            flash("User key not found. Please try logging in again.", "danger")
            return redirect(url_for('dashboard'))
        
        cipher_suite = Fernet(user_key)
        encrypted_data = cipher_suite.encrypt(file.read())

        binary_data = ''.join(format(byte, '08b') for byte in encrypted_data)

        cover_image_path = 'static/logo.jpg'
        if not os.path.exists(cover_image_path):
            flash("Cover image not found.", "danger")
            return redirect(url_for('dashboard'))

        cover_image = Image.open(cover_image_path).convert("RGB")
        pixels = np.array(cover_image)

        if len(binary_data) > pixels.shape[0] * pixels.shape[1]:
            flash("Cover image is too small to hold the data.", "danger")
            return redirect(url_for('dashboard'))

        index = 0
        for x in range(pixels.shape[0]):
            for y in range(pixels.shape[1]):
                if index < len(binary_data):
                    r, g, b = pixels[x, y]
                    r = int(bin(r)[:-1] + binary_data[index], 2)
                    pixels[x, y] = (r, g, b)
                    index += 1

        stego_image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_files', filename + "_stego.png")
        stego_image = Image.fromarray(pixels)
        stego_image.save(stego_image_path)
        logging.debug(f"Stego-image saved at {stego_image_path}")

        flash("File uploaded and hidden in stego-image successfully.", "success")
        return redirect(url_for('dashboard'))
    else:
        flash("No file provided for upload.", "danger")
        return redirect(url_for('dashboard'))

# Route for the Download Page, showing available files
@app.route('/download_page')
@key_required
def download_page():
    encrypted_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_files')
    files = [f.replace('_stego.png', '') for f in os.listdir(encrypted_folder) if f.endswith('_stego.png')]

    logging.debug(f"Available encrypted files for download: {files}")
    if not files:
        flash("No files available for download.", "info")
    
    return render_template('download_page.html', files=files)

# Route to download a file, extracted and decrypted from a stego-image
@app.route('/download/<filename>')
@key_required
def download_file(filename):
    stego_image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_files', filename + "_stego.png")
    user_key = load_user_key("user")
    if user_key is None:
        flash("User key not found. Please try logging in again.", "danger")
        return redirect(url_for('download_page'))

    cipher_suite = Fernet(user_key)
    stego_image = Image.open(stego_image_path).convert("RGB")
    pixels = np.array(stego_image)

    binary_data = ""
    for x in range(pixels.shape[0]):
        for y in range(pixels.shape[1]):
            r, g, b = pixels[x, y]
            binary_data += bin(r)[-1]

    encrypted_data = bytes(int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8))

    try:
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        decrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted_' + filename)
        with open(decrypted_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)

        logging.debug(f"Decrypted file saved to {decrypted_path}")
        return send_from_directory(app.config['UPLOAD_FOLDER'], 'decrypted_' + filename, as_attachment=True)
    except Exception as e:
        logging.error(f"Error during decryption: {e}")
        flash("Error during file decryption.", "danger")
        return redirect(url_for('download_page'))

if __name__ == '__main__':
    app.run(debug=True)
