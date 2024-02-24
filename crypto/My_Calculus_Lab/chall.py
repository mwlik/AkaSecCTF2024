from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import sympy as sp
import random

FLAG = b'AKASEC{fake_flag}'

key = random.getrandbits(7)

x = sp.symbols('x')

f = "REDACTED"
f_prime = "REDACTED"
f_second_prime = "REDACTED"

assert(2*f_second_prime - 6*f_prime + 3*f == 0)
assert(f.subs(x, 0) | f_prime.subs(x, 0) == 14)

def encrypt(message, key):
    global f
    global x
    point = f.subs(x, key)
    point_hash = hashlib.sha256(str(point).encode()).digest()
    cipher = AES.new(point_hash, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    nonce = cipher.nonce
    return ciphertext.hex(), nonce, tag


encrypted = encrypt(FLAG, key)

print(f"Key: {key}")
print(f"Encrypted: {encrypted}")
