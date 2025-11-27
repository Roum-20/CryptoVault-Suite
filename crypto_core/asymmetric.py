from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_rsa_keypair(
    key_size: int = 2048,
    password: Optional[str] = None,
) -> Tuple[bytes, bytes]:
    """Generate an RSA private+public key pair in PEM format."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    if password:
        enc_alg = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        enc_alg = serialization.NoEncryption()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_alg,
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def save_key(pem: bytes, path: Path) -> None:
    path.write_bytes(pem)


def load_private_key(path: Path, password: Optional[str] = None):
    pdata = path.read_bytes()
    return serialization.load_pem_private_key(
        pdata,
        password=password.encode("utf-8") if password else None,
    )


def load_public_key(path: Path):
    pdata = path.read_bytes()
    return serialization.load_pem_public_key(pdata)


def encrypt_bytes(public_pem: bytes, data: bytes) -> bytes:
    """Encrypt small data blobs with RSA public key."""
    public_key = serialization.load_pem_public_key(public_pem)
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


def decrypt_bytes(
    private_pem: bytes,
    ciphertext: bytes,
    password: Optional[str] = None,
) -> bytes:
    private_key = serialization.load_pem_private_key(
        private_pem,
        password=password.encode("utf-8") if password else None,
    )
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext


def sign_bytes(
    private_pem: bytes,
    data: bytes,
    password: Optional[str] = None,
) -> bytes:
    private_key = serialization.load_pem_private_key(
        private_pem,
        password=password.encode("utf-8") if password else None,
    )
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def verify_bytes(public_pem: bytes, data: bytes, signature: bytes) -> bool:
    public_key = serialization.load_pem_public_key(public_pem)
    from cryptography.exceptions import InvalidSignature
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
