from crypto_lab.rsa_edu import *

print("Вивід fast_pow_mod")
val, steps = fast_pow_mod(7, 13, 100)
print(val) # очікується 7 (бо 7^4 ≡ 1 mod 100)
for s in steps:
    print(s) # протокол «квадрат і множення»

print("\nРезультати тесту простоти")
print(is_probable_prime(7919)) # True — просте
print(is_probable_prime(7917)) # False — складене

print("\nРозрахунок d розширеним алгоритмом Евкліда")
print(egcd(240, 46)) # (2, ...) — НСД дорівнює 2

print("\nКонтрольний приклад p = 61, q = 53, e = 17")
p, q, e = 61, 53, 17
n, phi = p * q, (p - 1) * (q - 1)
d = modinv(e, phi)
c = encrypt(65, e, n)
m = decrypt(c, d, n)
print(f"n = {n}")
print(f"phi = {phi}")
print(f"d = {d}")
print(f"c = {c}")
print(f"decrypted m (65) = {m}")