from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity, decode_token
)
import string
import random

app = Flask(__name__)

FLAG = "AKASEC{fake_flag}"

def generate_string(length):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

app.config['JWT_SECRET_KEY'] = generate_string(2)
jwt = JWTManager(app)

users = {
    "user": {"username": "user", "password": generate_string(2), "role": "user"},
    "admin": {"username": "admin", "password": generate_string(32), "role": "admin"}
}

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    user = users.get(username, None)
    if user and password == user['password']:
        access_token = create_access_token(identity=user)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Bad username or password"}), 401

@app.route('/flag', methods=['GET'])
@jwt_required()
def flag():
    current_user = get_jwt_identity()
    if current_user["role"] == "admin":
        return jsonify({"flag": FLAG}), 200
    else:
        return jsonify({"msg": "You are not an admin!"}), 403

if __name__ == '__main__':
    app.run(debug=True)
