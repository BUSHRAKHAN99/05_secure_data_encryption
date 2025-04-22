# 📚 Secure Data Encryption System

Welcome to the **Secure Data Encryption System** – a simple and safe way to **store and retrieve encrypted data** using Streamlit! 🔐

This app uses **Fernet encryption** and **passkey hashing** to protect your sensitive data, along with a built-in **login system** and **lockout mechanism** for extra security.

---

## 🚀 Features

- 🔐 **Encrypt & Store Data** – Add private notes or data securely.
- 🧠 **Passkey Protected** – Each item is encrypted with your passkey.
- 👤 **Login System** – Log in using a username and secure passkey.
- 🕵️‍♂️ **Retrieve Data** – Decrypt your info only with the correct passkey.
- 🚫 **Brute-Force Protection** – 3 failed attempts? You're locked out for 30 minutes.
- 💾 **Auto-Save** – All data is saved in `stored_data.json`.

---

## 🎯 How It Works

1. 🔑 **Login** with your username and passkey.
2. 📂 **Store Data** securely using encryption.
3. 🔍 **Retrieve Data** by providing your encrypted string and passkey.
4. 🔒 **Lockout Mechanism** protects against brute-force attacks.

---

## 🛠️ Setup Instructions

### 1. Clone the project

```bash
git clone https://github.com/your-username/secure-data-encryption.git
cd secure-data-encryption
```

### 2. Install Dependencies

```bash
pip install streamlit cryptography
```

### 3. (Optional) Set Fernet Key for consistent encryption

```bash
export FERNET_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
```

### 4. Run the App

```bash
streamlit run app.py
```

---

## 📁 Files

- `app.py` – The main Streamlit app
- `stored_data.json` – Your encrypted data (auto-created)

---

## 🧠 Example Use Cases

- 🔑 Save passwords or notes securely
- 🧾 Store encrypted medical, legal, or financial notes
- 👥 Teach encryption basics interactively

---

## 🧩 Tech Stack

- Python
- Streamlit
- Cryptography (Fernet, PBKDF2HMAC)
- JSON (for local storage)

---

## 🛡️ Security Notes

- Passkeys are **not stored as plain text**.
- Data is only decrypted if the **correct passkey** is entered.
- App locks users out after **3 incorrect tries**.

---

## 🧑‍💻 Created By

**BUSHRA_KHAN_99** – Developer of Secure Data Encryption System  
🎓 Great for students, hobbyists, and privacy-focused users.

---
