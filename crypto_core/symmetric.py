from __future__ import annotations

from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet


def generate_key() -> bytes:
    """Generate a new Fernet key."""
    return Fernet.generate_key()


def save_key(key: bytes, path: Path) -> None:
    """Save key bytes to file."""
    path.write_bytes(key)


def load_key(path: Path) -> Fernet:
    """Load Fernet key from file and return Fernet instance."""
    if not path.is_file():
        raise FileNotFoundError(f"Key file not found: {path}")
    key = path.read_bytes()
    return Fernet(key)


def encrypt_bytes(key: bytes, data: bytes) -> bytes:
    """Encrypt bytes with given key."""
    f = Fernet(key)
    return f.encrypt(data)


def decrypt_bytes(key: bytes, token: bytes) -> bytes:
    """Decrypt bytes with given key."""
    f = Fernet(key)
    return f.decrypt(token)


def encrypt_file(key: bytes, in_path: Path, out_path: Optional[Path] = None) -> bytes:
    """Encrypt file contents. If out_path is provided, save; always return ciphertext."""
    data = in_path.read_bytes()
    token = encrypt_bytes(key, data)
    if out_path is not None:
        out_path.write_bytes(token)
    return token


def decrypt_file(key: bytes, in_path: Path, out_path: Optional[Path] = None) -> bytes:
    """Decrypt file contents. If out_path is provided, save; always return plaintext."""
    token = in_path.read_bytes()
    data = decrypt_bytes(key, token)
    if out_path is not None:
        out_path.write_bytes(data)
    return data
