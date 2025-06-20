import sqlite3

DB_FILE = "secure_medical.db"  # our database

def setup_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY, 
        role TEXT, 
        salt TEXT, 
        password_hash TEXT,
        private_key BLOB, 
        public_key BLOB
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS files (
    file_id TEXT PRIMARY KEY,
    patient TEXT,
    doctor TEXT,
    ciphertext TEXT,
    signature TEXT,
    timestamp TEXT
)
    ''')
    c.execute('''CREATE TABLE IF NOT EXISTS file_keys (
        file_id TEXT, 
        user_email TEXT, 
        encrypted_key TEXT,
        FOREIGN KEY(file_id) REFERENCES files(file_id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS access_logs (
        log_id TEXT PRIMARY KEY,
        file_id TEXT,
        accessed_by TEXT,
        timestamp TEXT,
        encrypted_note TEXT,
        FOREIGN KEY(file_id) REFERENCES files(file_id)
    )''')
    conn.commit()
    return conn


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn