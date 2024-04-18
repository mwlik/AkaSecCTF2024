from Crypto.Cipher import AES
import hashlib
import sympy as sp
import math
import random

FLAG = b'AKASEC{W484913491314184C}'

key = random.getrandbits(7)

x = sp.symbols('x')

f = (2 + (8/3)*math.sqrt(3))*math.e**(((3+math.sqrt(3))/2)*x) + (2 - (8/3)*math.sqrt(3))*math.e**(((3-math.sqrt(3))/2)*x)

def encrypt(message, key):
    global f
    global x
    point = f.subs(x, key)
    point_hash = hashlib.sha256(str(point).encode()).digest()
    cipher = AES.new(point_hash, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    nonce = cipher.nonce
    return ciphertext.hex(), nonce, tag

def decrypt(ciphertext, key, tag , nonce):
    global f
    global x
    point = f.subs(x, key)
    point_hash = hashlib.sha256(str(point).encode()).digest()
    cipher = AES.new(point_hash, AES.MODE_EAX, nonce)
    message = cipher.decrypt_and_verify(bytes.fromhex(ciphertext), tag)
    return message

ciphertext, nonce, tag = encrypt(FLAG, key)
message = decrypt(ciphertext, key, tag, nonce)

print(f"Key: {key}")
print(f"Encrypted: {ciphertext}")
print(f"Decrypted: {message}")
