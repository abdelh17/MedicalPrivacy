import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from db import get_db

# cryptographic functions
backend = default_backend()


def b64e(b): return base64.b64encode(b).decode()


def b64d(s): return base64.b64decode(s)


# function to hash a password, using PBKDF2 with SHA-256
# returns salt and hashed password
# used when registering a new user and for password verification, that's why default no salt (we generate one) otherwise we use the one provided to compare the given password.
def hash_password(password, salt=None):
    salt = salt or os.urandom(16)
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 100000, backend)
    return salt, kdf.derive(password.encode())


# encrypt data with provided AES key
def encrypt_aes(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend)
    return iv + cipher.encryptor().update(data) + cipher.encryptor().finalize()


# decrypt data with provided AES key
def decrypt_aes(ciphertext, key):
    iv, ciphertext = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend)
    return cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()


# encrypt key with RSA public key
def rsa_encrypt(key, pub):
    return pub.encrypt(  # encrypt with public key
        key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
    )


# decrypt key with RSA private key
def rsa_decrypt(ct, priv):
    return priv.decrypt(  # decrypt with private key
        ct,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None)
    )


# sign a message with RSA private key
def sign(priv, msg):
    return priv.sign(  # sign with private key
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )


# verify a signature with RSA public key
def verify(pub, sig, msg):
    try:
        pub.verify(  # verify sign with public key
            sig,
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True  # no error is raised, signature is valid
    except:
        return False  # error is raised, signature is not valid


# Load user's private and public keys from the database
def load_keys(email):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT private_key, public_key FROM users WHERE email=?", (email,))
    row = cursor.fetchone()
    conn.close()
    if not row: return None, None  # means user not found

    # return key that can be used to call functions .sign() .verify() .decrypt() .encrypt()
    priv = serialization.load_pem_private_key(row['private_key'], None, backend)
    pub = serialization.load_pem_public_key(row['public_key'], backend)
    return priv, pub
