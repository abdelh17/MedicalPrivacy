# 🔐 MedicalPrivacy – Encrypted Medical Record System

SecureMed is a Flask-based web application designed to securely manage medical records. It uses **AES encryption** for medical data, **RSA** for key sharing, **digital signatures** for authenticity, and includes **access logging** for transparency.

---

## Project Structure

```
MedicalPrivacy/
│
├── app.py                 # Main Flask application
├── auth.py                # Handles user registration and login
├── crypto_utils.py        # AES/RSA encryption/decryption, signing, verification
├── db.py                  # Database setup and connection
├── medical_data.py        # Functions to write/read medical files and logs
├── templates/             # HTML pages for the web interface
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── write_note.html
│   ├── view_chart.html
│   ├── view_chart_form.html
│   ├── access_logs.html
│   └── access_logs_form.html
├── static/
│   └── style.css          # CSS styles
├── secure_medical.db      # SQLite database (created at runtime for the purposes of this project)
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

---

## Features

- Role-based access: `patient`, `doctor`, `hospital`
  - Patients can view their own records and see the access logs of their records
  - Doctors can write and view patient records
  - Hospitals can view all access logs on patient records
- Encrypted file storage with AES
- RSA-encrypted symmetric keys for sharing with authorized users
- Digital signatures to verify author
- Access log to track who viewed what, when

---

## How to Run
### Clone the repository
```bash
git clone https://github.com/abdelh17/MedicalPrivacy.git
cd MedicalPrivacy
```

### 1. Create a Virtual Environment

**On macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**On Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
```

---

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 3. Start the App

```bash
python app.py
```

- Visit: [http://localhost:5000](http://localhost:5000) or [http://127.0.0.1:5000/](http://127.0.0.1:5000/)

---

## Security Design Overview

- **AES** encrypts each file/note with a unique key
- **RSA** encrypts the AES key for each recipient (doctor, patient, hospital)
- **Digital signatures** verify authenticity of notes using RSA
- **Encrypted timestamps** and access logs for auditability

---
