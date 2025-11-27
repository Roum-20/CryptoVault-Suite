# 🔐 CryptoVault Suite

**CryptoVault Suite** is a Streamlit-based cryptography toolkit that demonstrates:

- Modern cryptography (hashing, symmetric, asymmetric)
- Classical cipher techniques (Caesar, Vigenère, Rail Fence, etc.)
- Logging of all operations performed in the UI

It is designed as a **mini/major academic project** to showcase practical implementation of cryptographic concepts with a clean graphical interface.

---

## 🌟 Features

### 1. Hashing Module

- Uses Python’s `hashlib` library
- Supports all algorithms available in `hashlib.algorithms_guaranteed`, such as:
  - `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`
  - `blake2b`, `blake2s`
  - `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`
- Hash **text input**
- Hash **uploaded files**
- Displays hash digest in hexadecimal format

> 🔎 Note: Hashing is **one-way**; there is no “hash decryption”. Verification is done by re-hashing the original text and comparing.

---

### 2. Symmetric Encryption Module (Fernet)

- Uses `cryptography.fernet.Fernet`
- Symmetric algorithm (same key used for encryption & decryption)
- Internally uses AES + HMAC
- Features:
  - **Generate Fernet key**
  - Encrypt and decrypt **text**
  - Encrypt and decrypt **files** (content shown as text for demo)
- Input: base64-encoded Fernet key

---

### 3. Asymmetric Encryption Module (RSA)

- Uses RSA from `cryptography.hazmat.primitives.asymmetric.rsa`
- Operations implemented:
  - **Key generation**: 2048 / 3072 / 4096-bit keys
  - **RSA-OAEP encryption & decryption** (with SHA-256)
  - **RSA-PSS signatures** with SHA-256
  - **Signature verification**
- PEM format keys (Public & Private) are displayed in the UI

---

### 4. Classical Cipher Techniques Module

Implements traditional (pre-modern) ciphers:

- **Caesar Cipher**
- **Vigenère Cipher**
- **Rail Fence Cipher**
- **Atbash Cipher**
- **ROT-13**
- **Playfair Cipher** (5x5 matrix, I/J merged)

For each technique:

- Separate section for **Encryption**
- Separate section for **Decryption**
- Dynamic input fields:
  - Key (for Vigenère, Playfair)
  - Shift (for Caesar)
  - Number of rails (for Rail Fence)

This module is very useful for explaining the evolution from classical to modern cryptography in your report or viva.

---

### 5. Operation Logs / History

- Every operation (hash, encrypt, decrypt, sign, verify, classical cipher) is recorded
- Stored in `st.session_state` for the current session
- Viewable in the **History / Logs** expander in the sidebar
- You can **clear logs** using a button (logs are then reset and UI reruns)

---

## running step 
```bash
pip install -r requirements.txt
```
```bash
streamlit run app.py
```




