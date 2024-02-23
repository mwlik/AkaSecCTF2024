import sympy as sp
import random

FLAG = "AKASEC{fake_flag}"

key = random.getrandbits(7)

x = sp.symbols('x')

f = "REDACTED"
f_prime = "REDACTED"
f_second_prime = "REDACTED"

assert(2*f_second_prime - 6*f_prime + 3*f == 0)
assert(f.subs(x, 0) == 4 and f_prime.subs(x, 0) == 14)

def encrypt(message, key):
    global f
    global x
    point = f.subs(x, key)
    return [(ord(char) + int(point.evalf())) for char in message]

def decrypt(message, key):
    global f
    global x
    point = f.subs(x, key)
    return [(chr(int(code - int(point.evalf())))) for code in message]

encrypted = encrypt(FLAG, key)
decrypted = decrypt(encrypted, key)

print(f"Encrypted: {encrypted}")
print(f"Decrypted: {decrypted}")