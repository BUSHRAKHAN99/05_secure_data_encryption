import streamlit as st
import hashlib
import time
import json
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
from datetime import datetime, timedelta

# Load secret key securely (this would be set in an environment variable in a real production system)
KEY = os.environ.get("FERNET_KEY")  # Assume the key is stored as an environment variable
if not KEY:
    KEY = Fernet.generate_key()  # Fallback to a generated key if no environment variable is set
cipher = Fernet(KEY)

# Function to generate a PBKDF2 key from a passkey
def generate_pbkdf2_key(passkey, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

# Load data from a JSON file securely
def load_data():
    try:
        with open("stored_data.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

# Save data to a JSON file securely (ensure restricted access)
def save_data(data):
    try:
        with open("stored_data.json", "w") as f:
            json.dump(data, f)
    except PermissionError:
        st.error("⚠️ Unable to access data file. Ensure proper file permissions.")

# Initialize session state for storing data
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None  # Store time of the last failed attempt
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "user_data" not in st.session_state:
    st.session_state.user_data = {}

# Hash passkey using PBKDF2
def hash_passkey(passkey):
    salt = b'salt_value'  # You can change this to a dynamic value
    return generate_pbkdf2_key(passkey, salt)

# Function to encrypt data
def encrypt_data(text, passkey):
    encrypted_text = cipher.encrypt(text.encode()).decode()
    return encrypted_text

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    user_data = st.session_state.user_data
    for key, value in user_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0  # Reset failed attempts on successful decryption
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# Check if the user is locked out
def is_locked_out():
    if st.session_state.lockout_time:
        lockout_duration = timedelta(minutes=30)  # Lockout for 30 minutes after 3 failed attempts
        lockout_end_time = st.session_state.lockout_time + lockout_duration
        if datetime.now() < lockout_end_time:
            return True
    return False

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# --- Home ---
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

# --- Store Data ---
elif choice == "Store Data":
    if not st.session_state.current_user:
        st.warning("Please log in first.")
    else:
        st.subheader(f"📂 Store Data Securely for {st.session_state.current_user}")
        user_data = st.text_area("Enter Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Encrypt & Save"):
            if user_data and passkey:
                hashed_passkey = hash_passkey(passkey)
                encrypted_text = encrypt_data(user_data, passkey)
                st.session_state.user_data[st.session_state.current_user][encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
                save_data(st.session_state.user_data)
                st.success("✅ Data stored securely!")
            else:
                st.error("⚠️ Both fields are required!")

# --- Retrieve Data ---
elif choice == "Retrieve Data":
    if not st.session_state.current_user:
        st.warning("Please log in first.")
    else:
        if is_locked_out():
            st.warning("🔒 Too many failed attempts. Please try again later.")
        else:
            st.subheader(f"🔍 Retrieve Your Data ({st.session_state.current_user})")
            encrypted_text = st.text_area("Enter Encrypted Data:")
            passkey = st.text_input("Enter Passkey:", type="password")

            if st.button("Decrypt"):
                if encrypted_text and passkey:
                    decrypted_text = decrypt_data(encrypted_text, passkey)

                    if decrypted_text:
                        st.success(f"✅ Decrypted Data: {decrypted_text}")
                    else:
                        st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")

                        if st.session_state.failed_attempts >= 3:
                            st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                            st.session_state.failed_attempts = 0  # Reset failed attempts after redirect
                            st.experimental_rerun()  # Rerun the app to force the user to log in
                else:
                    st.error("⚠️ Both fields are required!")

# --- Login ---
elif choice == "Login":
    if is_locked_out():
        st.warning("🔒 Too many failed attempts. Please try again later.")
    else:
        st.subheader("🔑 Reauthorization Required")
        username = st.text_input("Username:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Login"):
            if username in st.session_state.user_data:
                if hash_passkey(passkey) == st.session_state.user_data[username]["passkey"]:
                    st.session_state.failed_attempts = 0  # Reset failed attempts on successful login
                    st.session_state.current_user = username
                    st.success(f"✅ Successfully logged in as {username}!")
                    st.experimental_rerun()
                else:
                    st.session_state.failed_attempts += 1
                    if st.session_state.failed_attempts == 3:
                        st.session_state.lockout_time = datetime.now()
                    st.error("❌ Incorrect passkey!")
            else:
                st.error("❌ User not found!")
