import streamlit as st
from cryptography.fernet import Fernet
import hashlib

# -------------------- Globals --------------------
stored_data = {}
login_password = "admin123"  # For reauthorization
failed_attempts = {}

# -------------------- Utility Functions --------------------
def generate_key(passkey: str) -> bytes:
    """Generate a Fernet key using the SHA-256 hash of the passkey."""
    hashed = hashlib.sha256(passkey.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(hashed))

def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text: str, passkey: str) -> (str, str):
    key = hashlib.sha256(passkey.encode()).digest()
    fernet = Fernet(base64.urlsafe_b64encode(key))
    encrypted = fernet.encrypt(text.encode())
    return encrypted.decode(), hash_passkey(passkey)

def decrypt_data(encrypted_text: str, passkey: str) -> str:
    key = hashlib.sha256(passkey.encode()).digest()
    fernet = Fernet(base64.urlsafe_b64encode(key))
    return fernet.decrypt(encrypted_text.encode()).decode()

# -------------------- Pages --------------------
def home():
    st.title("🔐 Secure Data Storage System")
    st.write("Choose an option below:")
    if st.button("Store New Data"):
        st.session_state.page = "insert"
    if st.button("Retrieve Stored Data"):
        st.session_state.page = "retrieve"

def insert_data():
    st.title("📝 Insert Data")
    username = st.text_input("Enter Username")
    text = st.text_area("Enter Text to Encrypt")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Encrypt and Store"):
        if username and text and passkey:
            encrypted_text, hashed_key = encrypt_data(text, passkey)
            stored_data[username] = {"encrypted_text": encrypted_text, "passkey": hashed_key}
            st.success("✅ Data securely stored!")
        else:
            st.warning("⚠️ Please fill in all fields.")

def retrieve_data():
    st.title("🔓 Retrieve Data")
    username = st.text_input("Enter Username")
    passkey = st.text_input("Enter Passkey", type="password")

    if username not in failed_attempts:
        failed_attempts[username] = 0

    if st.button("Decrypt"):
        if username in stored_data:
            stored_entry = stored_data[username]
            entered_hash = hash_passkey(passkey)

            if entered_hash == stored_entry["passkey"]:
                try:
                    decrypted = decrypt_data(stored_entry["encrypted_text"], passkey)
                    st.success(f"✅ Decrypted Data: {decrypted}")
                    failed_attempts[username] = 0  # Reset after success
                except Exception:
                    st.error("❌ Decryption failed due to wrong key format.")
            else:
                failed_attempts[username] += 1
                st.warning(f"⚠️ Incorrect Passkey! Attempts left: {3 - failed_attempts[username]}")
                if failed_attempts[username] >= 3:
                    st.session_state.page = "login"
        else:
            st.error("❌ Username not found.")

def login():
    st.title("🔐 Reauthorization Required")
    password = st.text_input("Enter Admin Password to Continue", type="password")

    if st.button("Login"):
        if password == login_password:
            st.success("✅ Logged in successfully. Try retrieving data again.")
            st.session_state.page = "retrieve"
            # Reset all failed attempts
            for key in failed_attempts:
                failed_attempts[key] = 0
        else:
            st.error("❌ Incorrect admin password.")

# -------------------- Routing --------------------
def main():
    if "page" not in st.session_state:
        st.session_state.page = "home"

    st.sidebar.title("📄 Navigation")
    nav = st.sidebar.radio("Go to", ["Home", "Insert Data", "Retrieve Data"])

    if nav == "Home":
        st.session_state.page = "home"
    elif nav == "Insert Data":
        st.session_state.page = "insert"
    elif nav == "Retrieve Data":
        st.session_state.page = "retrieve"

    if st.session_state.page == "home":
        home()
    elif st.session_state.page == "insert":
        insert_data()
    elif st.session_state.page == "retrieve":
        retrieve_data()
    elif st.session_state.page == "login":
        login()

if __name__ == "__main__":
    import base64  # Moved here to avoid import issues
    main()
