from __future__ import annotations

# ---------------- CLASSICAL CIPHERS ---------------- #

# 1. Caesar Cipher
def caesar_encrypt(text: str, shift: int) -> str:
    result = ""
    for c in text:
        if c.isalpha():
            base = "A" if c.isupper() else "a"
            result += chr((ord(c) - ord(base) + shift) % 26 + ord(base))
        else:
            result += c
    return result


def caesar_decrypt(text: str, shift: int) -> str:
    return caesar_encrypt(text, -shift)


# 2. Vigenère Cipher
def vigenere_encrypt(text: str, key: str) -> str:
    if not key:
        raise ValueError("Key must not be empty for Vigenère cipher.")
    key = key.lower()
    result = ""
    j = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[j % len(key)]) - ord("a")
            base = ord("A") if c.isupper() else ord("a")
            result += chr((ord(c) - base + shift) % 26 + base)
            j += 1
        else:
            result += c
    return result


def vigenere_decrypt(text: str, key: str) -> str:
    if not key:
        raise ValueError("Key must not be empty for Vigenère cipher.")
    key = key.lower()
    result = ""
    j = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[j % len(key)]) - ord("a")
            base = ord("A") if c.isupper() else ord("a")
            result += chr((ord(c) - base - shift) % 26 + base)
            j += 1
        else:
            result += c
    return result


# 3. Rail Fence Cipher (zig-zag)
def rail_encrypt(text: str, rails: int) -> str:
    if rails <= 1:
        return text
    fence = [[] for _ in range(rails)]
    row, step = 0, 1
    for ch in text:
        fence[row].append(ch)
        row += step
        if row == 0 or row == rails - 1:
            step *= -1
    return "".join("".join(r) for r in fence)


def rail_decrypt(cipher: str, rails: int) -> str:
    if rails <= 1:
        return cipher
    length = len(cipher)
    # mark zig-zag positions
    pattern = [["\n"] * length for _ in range(rails)]
    row, step = 0, 1
    for col in range(length):
        pattern[row][col] = "*"
        row += step
        if row == 0 or row == rails - 1:
            step *= -1
    # fill cipher chars row-wise
    idx = 0
    for r in range(rails):
        for c in range(length):
            if pattern[r][c] == "*" and idx < length:
                pattern[r][c] = cipher[idx]
                idx += 1
    # read zig-zag
    result = []
    row, step = 0, 1
    for col in range(length):
        result.append(pattern[row][col])
        row += step
        if row == 0 or row == rails - 1:
            step *= -1
    return "".join(result)


# 4. Atbash Cipher
def atbash(text: str) -> str:
    mapping = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba",
    )
    return text.translate(mapping)


# 5. ROT13 (special Caesar)
def rot13(text: str) -> str:
    return caesar_encrypt(text, 13)


# 6. Playfair Cipher (simplified 5x5, I/J merged)
def _playfair_generate_matrix(keyword: str):
    keyword = keyword.upper().replace("J", "I")
    matrix = []
    used = set()
    for c in keyword + "".join(chr(i) for i in range(65, 91)):  # A-Z
        if c not in used and c != "J":
            used.add(c)
            matrix.append(c)
    # 5x5 matrix
    return [matrix[i : i + 5] for i in range(0, 25, 5)]


def playfair_encrypt(text: str, key: str) -> str:
    if not key:
        raise ValueError("Key must not be empty for Playfair cipher.")

    matrix = _playfair_generate_matrix(key)
    text = text.upper().replace("J", "I").replace(" ", "")
    # make digraphs, insert X for odd length
    if len(text) % 2 != 0:
        text += "X"
    result = ""

    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        ra = ca = rb = cb = 0
        for r in range(5):
            if a in matrix[r]:
                ra, ca = r, matrix[r].index(a)
            if b in matrix[r]:
                rb, cb = r, matrix[r].index(b)
        if ra == rb:  # same row
            result += matrix[ra][(ca + 1) % 5] + matrix[rb][(cb + 1) % 5]
        elif ca == cb:  # same column
            result += matrix[(ra + 1) % 5][ca] + matrix[(rb + 1) % 5][cb]
        else:  # rectangle
            result += matrix[ra][cb] + matrix[rb][ca]
    return result


def playfair_decrypt(text: str, key: str) -> str:
    if not key:
        raise ValueError("Key must not be empty for Playfair cipher.")

    matrix = _playfair_generate_matrix(key)
    result = ""
    text = text.upper().replace(" ", "")

    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        ra = ca = rb = cb = 0
        for r in range(5):
            if a in matrix[r]:
                ra, ca = r, matrix[r].index(a)
            if b in matrix[r]:
                rb, cb = r, matrix[r].index(b)
        if ra == rb:  # same row
            result += matrix[ra][(ca - 1) % 5] + matrix[rb][(cb - 1) % 5]
        elif ca == cb:  # same column
            result += matrix[(ra - 1) % 5][ca] + matrix[(rb - 1) % 5][cb]
        else:  # rectangle
            result += matrix[ra][cb] + matrix[rb][ca]
    return result
