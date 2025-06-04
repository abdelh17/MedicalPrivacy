#Authentication (email/password) using hashed + salted passwords
#AES encryption for medical files (symmetric)
#RSA encryption for secure key exchange (AES)
#Digital signatures to verify author authenticity
#Hashing for password storage (PBKDF2-HMAC)

#SQLite for persistent storage (Python’s sqlite3): Create tables for users and files and replace in-memory dicts USERS_DB and FILES_DB with DB queries
#secure_medical.db: users storing encrypted credentials & RSA keys and files storing encrypted content and signatures

#bash: pip install cryptography

import os
import sqlite3
import uuid
import base64
from getpass import getpass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()

# --- Database Setup ---
conn = sqlite3.connect("secure_medical.db")
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    role TEXT,
    salt TEXT,
    password_hash TEXT,
    private_key BLOB,
    public_key BLOB
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS files (
    file_id TEXT PRIMARY KEY,
    sender TEXT,
    recipient TEXT,
    ciphertext TEXT,
    encrypted_key TEXT,
    signature TEXT
)
''')
conn.commit()

# --- Crypto Functions ---
def hash_password(password: str, salt: bytes = None):
    salt = salt or os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend)
    return salt, kdf.derive(password.encode())

def encrypt_file(data: bytes, symmetric_key: bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

def decrypt_file(ciphertext: bytes, symmetric_key: bytes):
    iv, ct = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def sign_data(private_key, data: bytes):
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def verify_signature(public_key, signature, data: bytes):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except:
        return False

def encrypt_symmetric_key(symmetric_key: bytes, recipient_public_key):
    return recipient_public_key.encrypt(
        symmetric_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_symmetric_key(encrypted_key: bytes, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

# --- User Management ---
def register_user(email, password, role):
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    if cursor.fetchone():
        print("User already exists.")
        return

    salt, password_hash = hash_password(password)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=backend)
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    cursor.execute('''
    INSERT INTO users (email, role, salt, password_hash, private_key, public_key)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (email, role, base64.b64encode(salt).decode(), base64.b64encode(password_hash).decode(), private_bytes, public_bytes))
    conn.commit()
    print("User registered.")

def authenticate(email, password):
    cursor.execute("SELECT salt, password_hash FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    if not row:
        return False
    salt = base64.b64decode(row[0])
    stored_hash = base64.b64decode(row[1])
    _, derived_hash = hash_password(password, salt)
    return derived_hash == stored_hash

def load_user_keys(email):
    cursor.execute("SELECT private_key, public_key FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    if not row:
        return None
    private_key = serialization.load_pem_private_key(row[0], password=None, backend=backend)
    public_key = serialization.load_pem_public_key(row[1], backend=backend)
    return private_key, public_key

# --- File Handling ---
def send_medical_file(sender_email, recipient_email, message):
    symmetric_key = os.urandom(32)
    ciphertext = encrypt_file(message.encode(), symmetric_key)

    _, recipient_pub = load_user_keys(recipient_email)
    sender_priv, _ = load_user_keys(sender_email)

    encrypted_key = encrypt_symmetric_key(symmetric_key, recipient_pub)
    signature = sign_data(sender_priv, ciphertext)

    file_id = str(uuid.uuid4())
    cursor.execute('''
    INSERT INTO files (file_id, sender, recipient, ciphertext, encrypted_key, signature)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        file_id,
        sender_email,
        recipient_email,
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(encrypted_key).decode(),
        base64.b64encode(signature).decode()
    ))
    conn.commit()
    print(f"File sent! File ID: {file_id}")

def read_medical_file(email, password, file_id):
    if not authenticate(email, password):
        print("Authentication failed.")
        return

    cursor.execute("SELECT * FROM files WHERE file_id = ? AND recipient = ?", (file_id, email))
    file = cursor.fetchone()
    if not file:
        print("Access denied or file not found.")
        return

    _, user_priv = load_user_keys(email)
    sender = file[1]
    ciphertext = base64.b64decode(file[3])
    encrypted_key = base64.b64decode(file[4])
    signature = base64.b64decode(file[5])

    _, sender_pub = load_user_keys(sender)
    symmetric_key = decrypt_symmetric_key(encrypted_key, user_priv)

    if not verify_signature(sender_pub, signature, ciphertext):
        print("Signature verification failed.")
        return

    plaintext = decrypt_file(ciphertext, symmetric_key)
    print(f"\n--- Decrypted Message ---\nFrom: {sender}\n{plaintext.decode()}")

# --- CLI ---
def main():
    while True:
        print("\n1. Register\n2. Send File\n3. Read File\n4. Exit")
        choice = input("Choice: ")
        if choice == '1':
            email = input("Email: ")
            password = getpass("Password: ")
            role = input("Role (patient/doctor/hospital): ")
            register_user(email, password, role)
        elif choice == '2':
            sender = input("Your email: ")
            recipient = input("Recipient email: ")
            message = input("Medical message: ")
            send_medical_file(sender, recipient, message)
        elif choice == '3':
            email = input("Your email: ")
            password = getpass("Your password: ")
            file_id = input("Enter file ID: ")
            read_medical_file(email, password, file_id)
        elif choice == '4':
            break

if __name__ == "__main__":
    main()