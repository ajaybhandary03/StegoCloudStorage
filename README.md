# StegoCloudStorage Project

## Overview
StegoCloudStorage is a secure cloud storage platform that uses steganography to embed encrypted files within images, ensuring data security and inconspicuous storage. The project allows users to upload files, which are encrypted and hidden within a cover image (`logo.png`), and download the embedded files using a unique stego-image key for decryption.

## Features
- **User Authentication**: Users log in using a unique stego-image key.
- **File Encryption and Steganography**: Uploaded files are encrypted and embedded into `logo.png` as stego-images.
- **Secure File Retrieval**: Users can download and decrypt embedded files using their unique key.

## Prerequisites
- **Python 3.7 or higher**
- **pip** (Python package installer)

## Installation Instructions
Clone the Repository:
   ```bash
   git clone https://github.com/username/StegoCloudStorage.git
   cd StegoCloudStorage

Create a Virtual Environment:

bash
Copy code
python -m venv venv
Activate the Virtual Environment:

Windows:
bash
Copy code
venv\Scripts\activate
Mac/Linux:
bash
Copy code
source venv/bin/activate
Install Required Packages:

bash
Copy code
pip install -r requirements.txt
How to Run the Project
Generate the Initial Stego-Image Key: Run the app.py script to create a unique stego-image key for the demo user.

bash
Copy code
python app.py
Access the Web Application: Open a web browser and navigate to http://127.0.0.1:5000/.

Login to the Application:

Use the stego-image (e.g., user_stego.png located in static/uploads/stego_keys/) to log in by uploading it on the login page.
Upload a File:

After successful login, navigate to the file upload section.
Select a file to upload. The application encrypts the file and embeds it in logo.png using steganography, saving it as a stego-image in static/uploads/encrypted_files/.
Download a File:

Navigate to the download page, select the desired embedded file, and download it.
The file will be decrypted and served for download using the original user key for decryption.
How the Project Works
1. User Authentication:
The user logs in by uploading their unique stego-image key, which contains an embedded cryptographic key.
2. File Encryption:
Files uploaded by the user are encrypted using Fernet symmetric encryption.
3. Steganography:
The encrypted data is converted to a binary format and embedded in the least significant bits (LSB) of the cover image (logo.png), creating a stego-image that visually resembles the original.
4. File Decryption and Retrieval:
When the user requests to download a file, the application extracts the embedded binary data from the stego-image, converts it back to bytes, and decrypts it using the unique key.
