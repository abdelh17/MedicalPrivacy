import hmac

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from crypto_utils import b64e, b64d, hash_password
from db import get_db

backend = default_backend()


# User registration/authentication

# Register a new user with email, password, and role
def register_user(email, password, role):
    conn = get_db()
    cursor = conn.cursor()
    # Check if user already exists
    if cursor.execute("SELECT email FROM users WHERE email=?", (email,)).fetchone():
        conn.close()
        return False, "User already exists"  # if user already exists, return False

    salt, hashed = hash_password(password)
    # Generate RSA keys for the user
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=backend)
    pub = priv.public_key()
    # Serialize keys to PEM format
    priv_bytes = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
    pub_bytes = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    # Store email, encrypted password, salt, role, and keys in the database
    cursor.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)", (
        email, role, b64e(salt), b64e(hashed), priv_bytes, pub_bytes
    ))
    conn.commit()
    conn.close()
    return True, "Registration successful"  # if registration is successful, return True


def authenticate_user(email, password):
    conn = get_db()
    cursor = conn.cursor()
    # Fetch user's salt and hashed password
    row = cursor.execute("SELECT salt, password_hash FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if not row: return False
    # Hash the password with the stored salt (after decryption (b64d()))
    _, derived = hash_password(password, b64d(row['salt']))
    return hmac.compare_digest(derived, b64d(row['password_hash']))  # compare passwords


def get_user_role(email):
    conn = get_db()
    cursor = conn.cursor()
    row = cursor.execute("SELECT role FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    return row['role'] if row else None
