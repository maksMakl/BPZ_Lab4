import hashlib
import hmac
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Допоміжні функції для звичайного AES-CBC з PKCS#7 padding
def cbc_encrypt(key: bytes, data: bytes) -> bytes:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv + enc.update(padded) + enc.finalize()


def cbc_decrypt(key: bytes, packet: bytes) -> bytes:
    iv, ct = packet[:16], packet[16:]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ВРАЗЛИВО: MAC-then-Encrypt (спочатку зняття padding, лише потім перевірка MAC)
def mte_encrypt(msg: bytes, enc_key: bytes, mac_key: bytes) -> bytes:
    mac = hmac.new(mac_key, msg, hashlib.sha256).digest()
    return cbc_encrypt(enc_key, msg + mac)


def mte_decrypt(packet: bytes, enc_key: bytes, mac_key: bytes) -> bytes:
    try:
        raw = cbc_decrypt(enc_key, packet)
    except ValueError:
        raise ValueError("Помилка 1: Невірний padding")

    msg, mac = raw[:-32], raw[-32:]
    expected = hmac.new(mac_key, msg, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise ValueError("Помилка 2: Невірний MAC (але padding був валідним)")
    return msg


# БЕЗПЕЧНО: Encrypt-then-MAC (спочатку перевірка MAC, потім розшифрування)
def etm_encrypt(msg: bytes, enc_key: bytes, mac_key: bytes) -> bytes:
    packet = cbc_encrypt(enc_key, msg)
    mac = hmac.new(mac_key, packet, hashlib.sha256).digest()
    return packet + mac


def etm_decrypt(data: bytes, enc_key: bytes, mac_key: bytes) -> bytes:
    packet, mac = data[:-32], data[-32:]
    expected = hmac.new(mac_key, packet, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise ValueError("Відхилено до розшифрування: невірний MAC")

    return cbc_decrypt(enc_key, packet)


if __name__ == "__main__":
    enc_key, mac_key = os.urandom(32), os.urandom(32)
    msg = b"Secret message"  # 14 Б + 32 Б MAC = 46 Б -> доповнення додає \x02\x02

    print("=== MAC-then-Encrypt (# ВРАЗЛИВО) ===")
    mte_packet = mte_encrypt(msg, enc_key, mac_key)
    for xor_mask in (0x01, 0x03):  # 0x02^0x01 = 0x03 (ламає padding); 0x02^0x03 = 0x01 (валідний padding)
        tampered = bytearray(mte_packet)
        tampered[-17] ^= xor_mask
        try:
            mte_decrypt(bytes(tampered), enc_key, mac_key)
        except ValueError as err:
            print(f"Маска {hex(xor_mask)} -> {err}")

    print("\n=== Encrypt-then-MAC (# БЕЗПЕЧНО) ===")
    etm_data = etm_encrypt(msg, enc_key, mac_key)
    for xor_mask in (0x01, 0x03):
        tampered = bytearray(etm_data)
        tampered[-49] ^= xor_mask  # те саме спотворення шифротексту
        try:
            etm_decrypt(bytes(tampered), enc_key, mac_key)
        except ValueError as err:
            print(f"Маска {hex(xor_mask)} -> {err}")