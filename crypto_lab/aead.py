"""Симетричне шифрування — КАРКАС для лабораторної роботи 4.

Здобувач реалізує шифрування за AEAD свого варіанта і демонструє наслідки
двох типових помилок зі свого завдання (ECB, повторний nonce тощо).
"""
from __future__ import annotations
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(plaintext: bytes, key: bytes, associated: bytes = b"") -> bytes:
    """БЕЗПЕЧНО: реалізуйте автентифіковане шифрування (AES-GCM / ChaCha20-Poly1305).

    Вимоги:
      – унікальний nonce на кожне повідомлення (лекція 10);
      – прив'язка асоційованих даних;
      – повернення nonce разом із шифротекстом і тегом.
    """
    # TODO(варіант): використати cryptography.hazmat.primitives.ciphers.aead
    if len(key) != 32:
        raise ValueError("AES-256-GCM вимагає ключ довжиною 32 байти (256 бітів)")

    nonce = os.urandom(12)
    aead = AESGCM(key)
    ciphertext_and_tag = aead.encrypt(nonce, plaintext, associated)
    return nonce + ciphertext_and_tag


def decrypt(blob: bytes, key: bytes, associated: bytes = b"") -> bytes:
    # TODO(варіант): перевірити тег автентичності; за розбіжності — підняти виняток.
    if len(key) != 32:
        raise ValueError("AES-256-GCM вимагає ключ довжиною 32 байти (256 бітів)")

    nonce = blob[:12]
    ct_and_tag = blob[12:]
    aead = AESGCM(key)
    return aead.decrypt(nonce, ct_and_tag, associated)

if __name__ == "__main__":
    key = b"0" * 32  # ТЕСТОВИЙ КЛЮЧ – не використовувати поза стендом
    blob = encrypt(b"secret payload", key, associated=b"hdr")
    assert decrypt(blob, key, associated=b"hdr") == b"secret payload"
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    try:
        decrypt(tampered, key, associated=b"hdr")
        print("ПОМИЛКА: підміну не виявлено")
    except Exception:
        print("ОК: тег відхилив підмінений шифротекст")