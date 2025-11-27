from __future__ import annotations

import base64
from datetime import datetime

import streamlit as st
import pandas as pd

from crypto_core import hashing, symmetric, asymmetric, classical

# -------------------- PAGE CONFIG -------------------- #
st.set_page_config(
    page_title="CryptoVault Suite",
    page_icon="🔐",
    layout="wide",
)

LOG_KEY = "crypto_logs"


# -------------------- LOGGING HELPERS -------------------- #
def init_logs():
    if LOG_KEY not in st.session_state:
        st.session_state[LOG_KEY] = []


def add_log(action: str, category: str, details: str):
    init_logs()
    st.session_state[LOG_KEY].append(
        {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "category": category,
            "action": action,
            "details": details,
        }
    )


def render_logs_sidebar():
    init_logs()
    with st.sidebar.expander("📜 History / Logs", expanded=False):
        if not st.session_state[LOG_KEY]:
            st.write("No logs yet.")
        else:
            df = pd.DataFrame(st.session_state[LOG_KEY])
            st.dataframe(df, use_container_width=True, hide_index=True)

            if st.button("Clear logs", key="log_clear_btn"):
                st.session_state[LOG_KEY] = []
                st.rerun()  # updated from experimental_rerun


# -------------------- HASHING UI -------------------- #
def ui_hashing():
    st.header("🔢 Hash Functions")

    algo = st.selectbox(
        "Algorithm",
        hashing.list_algorithms(),
        index=0,
        key="hash_algo_select",
    )
    mode = st.radio(
        "Input type",
        ["Text", "File"],
        horizontal=True,
        key="hash_input_mode",
    )

    if mode == "Text":
        text = st.text_area(
            "Text to hash",
            key="hash_text_area",
        )
        if st.button("Compute hash", type="primary", key="hash_text_btn"):
            if text:
                digest = hashing.hash_text(algo, text)
                st.subheader("Digest")
                st.code(digest)
                add_log("hash_text", "Hashing", f"{algo} | len={len(text)}")
            else:
                st.warning("Enter some text to hash.")
    else:
        uploaded = st.file_uploader(
            "Upload file to hash",
            key="hash_file_uploader",
        )
        if st.button("Compute file hash", type="primary", key="hash_file_btn"):
            if uploaded:
                data = uploaded.read()
                digest = hashing.hash_bytes(algo, data)
                st.subheader("Digest")
                st.code(digest)
                add_log("hash_file", "Hashing", f"{algo} | {uploaded.name}")
            else:
                st.warning("Upload a file first.")


# -------------------- SYMMETRIC (FERNET) UI -------------------- #
def ui_symmetric():
    st.header("🔐 Symmetric Encryption (Fernet)")

    tab_gen, tab_text, tab_file = st.tabs(
        ["Generate Key", "Text Encryption", "File Encryption"]
    )

    # --- Generate key ---
    with tab_gen:
        if st.button("Generate Fernet Key", key="sym_gen_key_btn"):
            key = symmetric.generate_key()
            st.subheader("Generated Key (base64)")
            st.code(key.decode("utf-8"))
            add_log("generate_fernet_key", "Symmetric", "New key generated")

    # --- Text encrypt/decrypt ---
    with tab_text:
        key = st.text_input(
            "Fernet Key (base64)",
            type="password",
            key="sym_text_key_input",
        )

        col_enc, col_dec = st.columns(2)

        with col_enc:
            st.markdown("**Encrypt Text**")
            plaintext = st.text_area(
                "Plaintext",
                key="sym_plaintext_area",
            )
            if st.button("Encrypt Text", key="sym_encrypt_text_btn"):
                if not key or not plaintext:
                    st.warning("Provide both key and plaintext.")
                else:
                    try:
                        token = symmetric.encrypt_bytes(
                            key.encode("utf-8"),
                            plaintext.encode("utf-8"),
                        )
                        st.subheader("Encrypted Token (base64)")
                        st.code(token.decode("utf-8"))
                        add_log(
                            "encrypt_text",
                            "Symmetric",
                            f"len(plaintext)={len(plaintext)}",
                        )
                    except Exception as e:
                        st.error(f"Error encrypting text: {e}")

        with col_dec:
            st.markdown("**Decrypt Text**")
            enc_text = st.text_area(
                "Encrypted Token (base64)",
                key="sym_encrypted_text_area",
            )
            if st.button("Decrypt Text", key="sym_decrypt_text_btn"):
                if not key or not enc_text:
                    st.warning("Provide both key and encrypted token.")
                else:
                    try:
                        plaintext = symmetric.decrypt_bytes(
                            key.encode("utf-8"),
                            enc_text.encode("utf-8"),
                        )
                        st.subheader("Decrypted Plaintext")
                        st.code(plaintext.decode("utf-8"))
                        add_log(
                            "decrypt_text",
                            "Symmetric",
                            f"len(ciphertext)={len(enc_text)}",
                        )
                    except Exception as e:
                        st.error(f"Error decrypting text: {e}")

    # --- File encrypt/decrypt ---
    with tab_file:
        key = st.text_input(
            "Fernet Key (base64) for files",
            type="password",
            key="sym_file_key_input",
        )
        mode = st.radio(
            "Mode",
            ["Encrypt file", "Decrypt file"],
            horizontal=True,
            key="sym_file_mode",
        )
        file = st.file_uploader(
            "Upload file for encryption/decryption",
            key="sym_file_uploader",
        )

        if st.button("Run Symmetric Operation", key="sym_file_run_btn"):
            if not key:
                st.warning("Provide a key.")
            elif file is None:
                st.warning("Upload a file.")
            else:
                data = file.read()
                try:
                    if mode == "Encrypt file":
                        token = symmetric.encrypt_bytes(
                            key.encode("utf-8"),
                            data,
                        )
                        st.subheader("Encrypted File Content (base64-like)")
                        st.code(token.decode("utf-8", errors="ignore"))
                        add_log(
                            "encrypt_file",
                            "Symmetric",
                            f"{file.name} | {len(data)} bytes",
                        )
                    else:
                        plaintext = symmetric.decrypt_bytes(
                            key.encode("utf-8"),
                            data,
                        )
                        st.subheader("Decrypted File Content (text view)")
                        st.code(plaintext.decode("utf-8", errors="ignore"))
                        add_log(
                            "decrypt_file",
                            "Symmetric",
                            f"{file.name} | {len(data)} bytes",
                        )
                except Exception as e:
                    st.error(f"Error processing file: {e}")


# -------------------- ASYMMETRIC (RSA) UI -------------------- #
def ui_asymmetric():
    st.header("🗝 RSA — Asymmetric Cryptography")

    tab_key, tab_text, tab_sign = st.tabs(
        ["Keypair", "Encrypt / Decrypt", "Sign / Verify"]
    )

    # --- Keypair generation ---
    with tab_key:
        size = st.selectbox(
            "Key Size (bits)",
            [2048, 3072, 4096],
            index=0,
            key="rsa_key_size_select",
        )
        pwd = st.text_input(
            "Private Key Password (optional)",
            type="password",
            key="rsa_key_password_input",
        )
        if st.button("Generate RSA Keypair", key="rsa_generate_keypair_btn"):
            try:
                priv_pem, pub_pem = asymmetric.generate_rsa_keypair(
                    key_size=size,
                    password=pwd or None,
                )
                st.subheader("Public Key (PEM)")
                st.code(pub_pem.decode("utf-8"))
                st.subheader("Private Key (PEM)")
                st.code(priv_pem.decode("utf-8"))
                add_log(
                    "rsa_generate_keypair",
                    "Asymmetric",
                    f"size={size}, password_protected={bool(pwd)}",
                )
            except Exception as e:
                st.error(f"Error generating keypair: {e}")

    # --- Encrypt / Decrypt ---
    with tab_text:
        col_enc, col_dec = st.columns(2)

        with col_enc:
            st.markdown("**Encrypt with Public Key (RSA-OAEP)**")
            pub_pem_text = st.text_area(
                "Public Key (PEM) for Encryption",
                key="rsa_pub_key_encrypt_area",
            )
            message = st.text_area(
                "Plaintext Message to Encrypt",
                key="rsa_message_encrypt_area",
            )
            if st.button("Encrypt Message", key="rsa_encrypt_btn"):
                if not pub_pem_text or not message:
                    st.warning("Provide both public key and message.")
                else:
                    try:
                        ciphertext = asymmetric.encrypt_bytes(
                            pub_pem_text.encode("utf-8"),
                            message.encode("utf-8"),
                        )
                        b64 = base64.b64encode(ciphertext).decode("utf-8")
                        st.subheader("Ciphertext (base64)")
                        st.code(b64)
                        add_log(
                            "rsa_encrypt",
                            "Asymmetric",
                            f"len(message)={len(message)}",
                        )
                    except Exception as e:
                        st.error(f"Error encrypting message: {e}")

        with col_dec:
            st.markdown("**Decrypt with Private Key (RSA-OAEP)**")
            priv_pem_text = st.text_area(
                "Private Key (PEM) for Decryption",
                key="rsa_priv_key_decrypt_area",
            )
            pwd = st.text_input(
                "Private Key Password (for Decryption)",
                type="password",
                key="rsa_decrypt_password_input",
            )
            ciphertext_b64 = st.text_area(
                "Ciphertext (base64)",
                key="rsa_ciphertext_decrypt_area",
            )
            if st.button("Decrypt Message", key="rsa_decrypt_btn"):
                if not priv_pem_text or not ciphertext_b64:
                    st.warning("Provide private key and ciphertext.")
                else:
                    try:
                        ciphertext = base64.b64decode(
                            ciphertext_b64.encode("utf-8")
                        )
                        plaintext = asymmetric.decrypt_bytes(
                            priv_pem_text.encode("utf-8"),
                            ciphertext,
                            password=pwd or None,
                        )
                        st.subheader("Decrypted Plaintext")
                        st.code(plaintext.decode("utf-8"))
                        add_log(
                            "rsa_decrypt",
                            "Asymmetric",
                            f"len(ciphertext_b64)={len(ciphertext_b64)}",
                        )
                    except Exception as e:
                        st.error(f"Error decrypting message: {e}")

    # --- Sign / Verify ---
    with tab_sign:
        col_sign, col_verify = st.columns(2)

        with col_sign:
            st.markdown("**Sign Message (RSA-PSS + SHA-256)**")
            priv_pem_text = st.text_area(
                "Private Key (PEM) for Signing",
                key="rsa_priv_key_sign_area",
            )
            pwd = st.text_input(
                "Private Key Password (for Signing)",
                type="password",
                key="rsa_sign_password_input",
            )
            message = st.text_area(
                "Message to Sign",
                key="rsa_message_sign_area",
            )
            if st.button("Generate Signature", key="rsa_sign_btn"):
                if not priv_pem_text or not message:
                    st.warning("Provide private key and message.")
                else:
                    try:
                        signature = asymmetric.sign_bytes(
                            priv_pem_text.encode("utf-8"),
                            message.encode("utf-8"),
                            password=pwd or None,
                        )
                        sig_b64 = base64.b64encode(signature).decode("utf-8")
                        st.subheader("Signature (base64)")
                        st.code(sig_b64)
                        add_log(
                            "rsa_sign",
                            "Asymmetric",
                            f"len(message)={len(message)}",
                        )
                    except Exception as e:
                        st.error(f"Error signing message: {e}")

        with col_verify:
            st.markdown("**Verify Signature (RSA-PSS + SHA-256)**")
            pub_pem_text = st.text_area(
                "Public Key (PEM) for Verification",
                key="rsa_pub_key_verify_area",
            )
            message = st.text_area(
                "Message to Verify",
                key="rsa_message_verify_area",
            )
            sig_b64 = st.text_area(
                "Signature (base64) to Verify",
                key="rsa_signature_verify_area",
            )
            if st.button("Verify Signature", key="rsa_verify_btn"):
                if not pub_pem_text or not message or not sig_b64:
                    st.warning("Provide public key, message, and signature.")
                else:
                    try:
                        signature = base64.b64decode(sig_b64.encode("utf-8"))
                        ok = asymmetric.verify_bytes(
                            pub_pem_text.encode("utf-8"),
                            message.encode("utf-8"),
                            signature,
                        )
                        if ok:
                            st.success("✅ Signature is VALID for this message.")
                        else:
                            st.error("❌ Signature is INVALID for this message.")
                        add_log(
                            "rsa_verify",
                            "Asymmetric",
                            f"valid={ok}, len(message)={len(message)}",
                        )
                    except Exception as e:
                        st.error(f"Error verifying signature: {e}")


# -------------------- CLASSICAL CIPHERS UI -------------------- #
def ui_classical():
    st.header("📜 Classical Cipher Techniques (Encrypt + Decrypt)")

    # --------- ENCRYPTION --------- #
    st.subheader("🔐 Encryption Techniques")
    encrypt_algo = st.selectbox(
        "Select Encryption Algorithm",
        [
            "Caesar Cipher",
            "Vigenère Cipher",
            "Rail Fence Cipher",
            "Atbash Cipher",
            "ROT-13",
            "Playfair Cipher",
        ],
        key="encrypt_algo_select",
    )

    enc_text = st.text_area("Enter Plaintext", key="encrypt_text_input")

    key_enc = None
    shift_enc = None
    rails_enc = None

    if encrypt_algo == "Caesar Cipher":
        shift_enc = st.slider("Shift Value", 1, 25, 3, key="enc_caesar_shift")
    elif encrypt_algo in ["Vigenère Cipher", "Playfair Cipher"]:
        key_enc = st.text_input("Key", key="enc_key_input")
    elif encrypt_algo == "Rail Fence Cipher":
        rails_enc = st.slider("Number of Rails", 2, 10, 3, key="enc_rails_input")

    if st.button("Encrypt Now", key="encrypt_now_btn"):
        try:
            if encrypt_algo == "Caesar Cipher":
                result = classical.caesar_encrypt(enc_text, shift_enc)
            elif encrypt_algo == "Vigenère Cipher":
                result = classical.vigenere_encrypt(enc_text, key_enc)
            elif encrypt_algo == "Rail Fence Cipher":
                result = classical.rail_encrypt(enc_text, rails_enc)
            elif encrypt_algo == "Atbash Cipher":
                result = classical.atbash(enc_text)
            elif encrypt_algo == "ROT-13":
                result = classical.rot13(enc_text)
            elif encrypt_algo == "Playfair Cipher":
                result = classical.playfair_encrypt(enc_text, key_enc)

            st.success(f"🔐 Encrypted using {encrypt_algo}")
            st.code(result)
            add_log("Encrypt", "Classical", encrypt_algo)

        except Exception as e:
            st.error(f"Encryption Error: {e}")

    st.markdown("---")

    # --------- DECRYPTION --------- #
    st.subheader("🔓 Decryption Techniques")
    decrypt_algo = st.selectbox(
        "Select Decryption Algorithm",
        [
            "Caesar Cipher",
            "Vigenère Cipher",
            "Rail Fence Cipher",
            "Atbash Cipher",
            "ROT-13",
            "Playfair Cipher",
        ],
        key="decrypt_algo_select",
    )

    dec_text = st.text_area("Enter Ciphertext", key="decrypt_text_input")

    key_dec = None
    shift_dec = None
    rails_dec = None

    if decrypt_algo == "Caesar Cipher":
        shift_dec = st.slider(
            "Shift Value (Decrypt)", 1, 25, 3, key="dec_caesar_shift"
        )
    elif decrypt_algo in ["Vigenère Cipher", "Playfair Cipher"]:
        key_dec = st.text_input("Key (Decrypt)", key="dec_key_input")
    elif decrypt_algo == "Rail Fence Cipher":
        rails_dec = st.slider(
            "Number of Rails (Decrypt)", 2, 10, 3, key="dec_rails_input"
        )

    if st.button("Decrypt Now", key="decrypt_now_btn"):
        try:
            if decrypt_algo == "Caesar Cipher":
                result = classical.caesar_decrypt(dec_text, shift_dec)
            elif decrypt_algo == "Vigenère Cipher":
                result = classical.vigenere_decrypt(dec_text, key_dec)
            elif decrypt_algo == "Rail Fence Cipher":
                result = classical.rail_decrypt(dec_text, rails_dec)
            elif decrypt_algo == "Atbash Cipher":
                result = classical.atbash(dec_text)
            elif decrypt_algo == "ROT-13":
                result = classical.rot13(dec_text)
            elif decrypt_algo == "Playfair Cipher":
                result = classical.playfair_decrypt(dec_text, key_dec)

            st.success(f"🔓 Decrypted using {decrypt_algo}")
            st.code(result)
            add_log("Decrypt", "Classical", decrypt_algo)

        except Exception as e:
            st.error(f"Decryption Error: {e}")


# -------------------- MAIN -------------------- #
def main():
    init_logs()

    st.title("🔐 CryptoVault Suite ")

    section = st.sidebar.radio(
        "Menu",
        ["Hashing", "Symmetric", "Asymmetric", "Classical Ciphers"],
        key="main_menu_radio",
    )

    render_logs_sidebar()

    if section == "Hashing":
        ui_hashing()
    elif section == "Symmetric":
        ui_symmetric()
    elif section == "Asymmetric":
        ui_asymmetric()
    else:
        ui_classical()


if __name__ == "__main__":
    main()
