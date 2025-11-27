from __future__ import annotations

import hashlib
from pathlib import Path
from typing import List


def list_algorithms() -> List[str]:
    """Return sorted list of available hash algorithms."""
    return sorted(hashlib.algorithms_guaranteed)


def _get_hasher(algorithm: str) -> "hashlib._Hash":
    algo = algorithm.lower()
    if algo not in hashlib.algorithms_available:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    return hashlib.new(algo)


def hash_bytes(algorithm: str, data: bytes) -> str:
    """Hash raw bytes and return hex digest."""
    h = _get_hasher(algorithm)
    h.update(data)
    return h.hexdigest()


def hash_text(algorithm: str, text: str, encoding: str = "utf-8") -> str:
    """Hash a text string (encoded to bytes)."""
    return hash_bytes(algorithm, text.encode(encoding))


def hash_file(algorithm: str, file_path: Path, chunk_size: int = 8192) -> str:
    """Hash file contents in chunks."""
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")
    h = _get_hasher(algorithm)
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()
