import os
import uuid
from datetime import datetime

from auth import authenticate_user, get_user_role
from crypto_utils import encrypt_aes, decrypt_aes, rsa_encrypt, rsa_decrypt, sign, verify, load_keys, b64e, b64d
from db import get_db


# Medical data
def write_to_chart(doctor, patient, content):
    # load keys
    doc_priv, doc_pub = load_keys(doctor)
    pat_priv, pat_pub = load_keys(patient)
    hosp_priv, hosp_pub = load_keys("hospital@system.com")
    if not pat_pub or not hosp_pub:
        return False, "Patient or hospital not registered"

    # Generate AES key per content
    aes_key = os.urandom(32)
    enc_data = encrypt_aes(content.encode(), aes_key)
    writing_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    enc_time = encrypt_aes(writing_time.encode(), aes_key)

    # Sign the encrypted data with doctor's private key
    sig = sign(doc_priv, enc_data)
    file_id = str(uuid.uuid4())

    conn = get_db()
    cursor = conn.cursor()

    # save patient, doctor, encrypted data, signature, and timestamp in the database
    cursor.execute("INSERT INTO files VALUES (?, ?, ?, ?, ?, ?)", (
        file_id, patient, doctor, b64e(enc_data), b64e(sig), b64e(enc_time)
    ))

    # Encrypt AES key for recipients
    recipients = [(patient, pat_pub), ("hospital@system.com", hosp_pub)]

    # get all doctors
    cursor.execute("SELECT email FROM users WHERE role='doctor'")
    all_doctors = cursor.fetchall()
    # fetch their public keys
    for doc_row in all_doctors:
        _, pub = load_keys(doc_row['email'])
        if pub:
            recipients.append((doc_row['email'], pub))

    # encrypt an AES key for each recipient (patient, all doctors, hospital account)
    for recipient_email, pubkey in recipients:
        try:
            enc_key = rsa_encrypt(aes_key, pubkey)
            cursor.execute("INSERT INTO file_keys VALUES (?, ?, ?)", (
                file_id, recipient_email, b64e(enc_key)
            ))
        except:
            continue

    conn.commit()
    conn.close()
    return True, "Data written successfully"


def log_access(file_id, viewer, aes_key):
    note = f"{viewer} accessed entry"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    enc_note = encrypt_aes(note.encode(), aes_key)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO access_logs VALUES (?, ?, ?, ?, ?)", (
        str(uuid.uuid4()), file_id, viewer, timestamp, b64e(enc_note)
    ))
    conn.commit()
    conn.close()


# read chart
def read_chart(viewer, password, patient=None):
    if not authenticate_user(viewer, password):
        return ["Invalid credentials"]

    role = get_user_role(viewer)
    if role == "patient":
        patient = viewer
    elif not patient:  # if the viewer is not a patient, they must specify a patient
        return ["Enter patient email"]

    conn = get_db()
    cursor = conn.cursor()
    # get all records for the patient
    cursor.execute("SELECT file_id, doctor, ciphertext, signature, timestamp FROM files WHERE patient=?", (patient,))
    records = cursor.fetchall()
    conn.close()

    viewer_priv, _ = load_keys(viewer)
    chart = [f"Medical Chart for {patient}:\n"]

    for record in records:
        file_id, doctor, ct_b64, sig_b64, ts_b64 = record['file_id'], record['doctor'], record['ciphertext'], record[
            'signature'], record['timestamp']
        ciphertext, signature, record_timestamp = b64d(ct_b64), b64d(sig_b64), b64d(
            ts_b64)  # get ciphertext, signature, timestamp
        _, doc_pub = load_keys(doctor)  # load doctor's public key
        if not verify(doc_pub, signature, ciphertext): continue  # verify signature

        conn = get_db()
        cursor = conn.cursor()
        # get the encrypted AES key for the viewer
        row = cursor.execute("SELECT encrypted_key FROM file_keys WHERE file_id=? AND user_email=?",
                             (file_id, viewer)).fetchone()
        conn.close()
        if not row: continue

        try:
            aes_key = rsa_decrypt(b64d(row['encrypted_key']),
                                  viewer_priv)  # decrypt AES key with viewer's private key (remember that it was encoded for all possible viewers)
            msg = decrypt_aes(ciphertext, aes_key).decode()
            record_timestamp = decrypt_aes(record_timestamp, aes_key).decode()
            log_access(file_id, viewer, aes_key)  # log access to the file
            chart.append(f"[{record_timestamp}] Entry by: {doctor}\n{msg}\n")
        except:
            continue

    return chart  # returns all entries in the chart


def read_access_logs(patient_email, viewer):
    role = get_user_role(viewer)
    if role not in ["hospital", "patient"]:  # only hospital and patient can view access logs
        return ["Access denied"]

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT file_id, timestamp FROM files WHERE patient=?", (patient_email,))
    records = cursor.fetchall()
    logs = []

    for record in records:
        file_id = record['file_id']
        cursor.execute("SELECT accessed_by, timestamp, encrypted_note FROM access_logs WHERE file_id=?", (file_id,))
        log_records = cursor.fetchall()

        for log_record in log_records:
            user, ts, enc_note = log_record['accessed_by'], log_record['timestamp'], log_record['encrypted_note']
            try:
                row = cursor.execute("SELECT encrypted_key FROM file_keys WHERE file_id=? AND user_email=?",
                                     (file_id, viewer)).fetchone()
                if not row: continue
                viewer_priv, _ = load_keys(viewer)
                aes_key = rsa_decrypt(b64d(row['encrypted_key']), viewer_priv)
                note = decrypt_aes(b64d(enc_note), aes_key).decode()
                logs.append(f"[{ts}] {user} → {note}")
            except:
                continue

    conn.close()
    return logs if logs else ["No access logs found."]
