from cryptography.fernet import Fernet

key = Fernet.generate_key()
print(f"Generated Fernet Key: {key.decode()}")
