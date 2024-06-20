import os
from cryptography.fernet import Fernet
import base64

def generate_key():
    key = Fernet.generate_key()
    return key

def encrypt_file(data, key):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)
    return encrypted_data

def decrypt_file(data, key):
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(data)
    return decrypted_data

def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def generate_verification_code():
    return base64.urlsafe_b64encode(os.urandom(4)).decode('utf-8')[:6]
