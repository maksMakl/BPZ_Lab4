from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

if __name__ == "__main__":
    # Генерація пари ключів
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    msg = b"lab4 demo message"

    # Підписування повідомлення
    sig = priv.sign(msg)

    # Перевірка коректного підпису (успіх - виняток не піднімається)
    pub.verify(sig, msg)
    print("Перевірка коректного підпису: УСПІХ")

    # Модифікація повідомлення
    tampered_msg = msg + b"x"
    try:
        pub.verify(sig, tampered_msg)
    except InvalidSignature:
        print("Перевірка зміненого повідомлення (msg + b'x'): підміну виявлено (InvalidSignature)")

    # Модифікація підпису
    tampered_sig = bytearray(sig)
    tampered_sig[0] ^= 0xFF
    try:
        pub.verify(bytes(tampered_sig), msg)
    except InvalidSignature:
        print("Перевірка зміненого підпису: підміну виявлено (InvalidSignature)")