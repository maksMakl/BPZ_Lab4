from crypto_lab.rsa_edu import *

k = keygen(bits=24)

print(k)
m = 42
c = encrypt(m, k["e"], k["n"])
assert decrypt(c, k["d"], k["n"]) == m
assert is_probable_prime(k["p"])
assert is_probable_prime(k["q"])
assert k["p"].bit_length() == k["q"].bit_length()
assert k["p"].bit_length() == 24
assert (k["e"] * k["d"]) % k["phi"] == 1