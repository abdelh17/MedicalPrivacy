#Authentication (email/password) using hashed + salted passwords
#AES encryption for medical files (symmetric)
#RSA encryption for secure key exchange (AES)
#Digital signatures to verify author authenticity
#Hashing for password storage (PBKDF2-HMAC)

#SQLite for persistent storage (Python’s sqlite3): Create tables for users and files and replace in-memory dicts USERS_DB and FILES_DB with DB queries
#secure_medical.db: users storing encrypted credentials & RSA keys and files storing encrypted content and signatures

#bash: pip install cryptography

import tkinter as tk
from tkinter import messagebox, simpledialog
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
        messagebox.showerror("Error", "User already exists.")
        return False

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
    return True

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
    cursor.execute("SELECT role FROM users WHERE email = ?", (sender_email,))
    sender_role = cursor.fetchone()[0]

    if sender_role == "patient":
        messagebox.showerror("Access Denied", "Patients cannot send files.")
        return

    if sender_role == "doctor" and recipient_email != "hospital@system":
        messagebox.showerror("Access Denied", "Doctors can only send files to the hospital.")
        return

    if sender_role == "hospital":
        cursor.execute("SELECT role FROM users WHERE email = ?", (recipient_email,))
        recipient_role = cursor.fetchone()
        if not recipient_role or recipient_role[0] != "patient":
            messagebox.showerror("Access Denied", "Hospital can only send files to patients.")
            return

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
    messagebox.showinfo("Success", f"File sent! File ID: {file_id}")

def read_files_for_user(email, password):
    if not authenticate(email, password):
        messagebox.showerror("Login Failed", "Invalid credentials.")
        return []

    cursor.execute("SELECT file_id, sender, ciphertext, encrypted_key, signature FROM files WHERE recipient = ?", (email,))
    files = cursor.fetchall()
    messages = []
    for file_id, sender, ciphertext_b64, encrypted_key_b64, signature_b64 in files:
        ciphertext = base64.b64decode(ciphertext_b64)
        encrypted_key = base64.b64decode(encrypted_key_b64)
        signature = base64.b64decode(signature_b64)

        _, user_priv = load_user_keys(email)
        _, sender_pub = load_user_keys(sender)

        symmetric_key = decrypt_symmetric_key(encrypted_key, user_priv)
        if not verify_signature(sender_pub, signature, ciphertext):
            continue

        decrypted = decrypt_file(ciphertext, symmetric_key).decode()
        messages.append(f"From: {sender}\n{decrypted}")
    return messages

# --- GUI ---
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Medical System")
        self.email = None
        self.role = None
        self.build_login()

    def build_login(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text="Email").pack()
        email_entry = tk.Entry(self.root)
        email_entry.pack()
        tk.Label(self.root, text="Password").pack()
        pw_entry = tk.Entry(self.root, show="*")
        pw_entry.pack()

        def login():
            email = email_entry.get()
            password = pw_entry.get()
            if authenticate(email, password):
                self.email = email
                cursor.execute("SELECT role FROM users WHERE email = ?", (email,))
                self.role = cursor.fetchone()[0]
                self.build_dashboard()
            else:
                messagebox.showerror("Login Failed", "Invalid credentials")

        tk.Button(self.root, text="Login", command=login).pack()
        tk.Button(self.root, text="Register", command=self.build_register).pack()

    def build_register(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text="Email").pack()
        email_entry = tk.Entry(self.root)
        email_entry.pack()
        tk.Label(self.root, text="Password").pack()
        pw_entry = tk.Entry(self.root, show="*")
        pw_entry.pack()
        tk.Label(self.root, text="Role").pack()
        role_entry = tk.Entry(self.root)
        role_entry.pack()

        def register():
            if register_user(email_entry.get(), pw_entry.get(), role_entry.get()):
                messagebox.showinfo("Success", "User registered.")
                self.build_login()

        tk.Button(self.root, text="Submit", command=register).pack()
        tk.Button(self.root, text="Back", command=self.build_login).pack()

    def build_dashboard(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text=f"Logged in as {self.email} ({self.role})").pack()
        if self.role in ["doctor", "hospital"]:
            tk.Button(self.root, text="Send Medical File", command=self.send_file_gui).pack()
        tk.Button(self.root, text="View Files", command=self.view_files_gui).pack()
        tk.Button(self.root, text="Logout", command=self.build_login).pack()

    def send_file_gui(self):
        recipient = simpledialog.askstring("Send File", "Recipient Email:")
        message = simpledialog.askstring("Message", "Enter medical message:")
        if recipient and message:
            send_medical_file(self.email, recipient, message)

    def view_files_gui(self):
        messages = read_files_for_user(self.email, simpledialog.askstring("Password", "Confirm your password:", show="*"))
        if messages:
            for msg in messages:
                messagebox.showinfo("File", msg)
        else:
            messagebox.showinfo("Info", "No messages found.")

# Run the GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()