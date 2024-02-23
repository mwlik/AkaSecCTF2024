import sympy as sp
import math
import random

FLAG = "AKASEC{W484913491314184C}"

key = random.getrandbits(7)

x = sp.symbols('x')

f = (2 + (8/3)*math.sqrt(3))*math.e**(((3+math.sqrt(3))/2)*x) + (2 - (8/3)*math.sqrt(3))*math.e**(((3-math.sqrt(3))/2)*x)

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

print(f"Key: {key}")
print(f"Encrypted: {encrypted}")
print(f"Decrypted: {decrypted}")