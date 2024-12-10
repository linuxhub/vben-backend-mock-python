#!/usr/bin/env python
# encoding: utf8

from flask import Flask, request, jsonify, make_response
from functools import wraps
import jwt
import datetime

# 初始化应用
app = Flask(__name__)
app.config['SECRET_KEY'] = 'access_token_secret'
app.config['REFRESH_SECRET_KEY'] = 'refresh_token_secret'

# 简单的内存数据库
MOCK_USERS = [
    {
        "id": 0,
        "password": "123456",
        "realName": "Vben",
        "roles": ["super"],
        "username": "vben",
    },
    {
        "id": 1,
        "password": "123456",
        "realName": "Admin",
        "roles": ["admin"],
        "username": "admin",
    },
    {
        "id": 2,
        "password": "123456",
        "realName": "Jack",
        "roles": ["user"],
        "username": "jack",
    },
]

MOCK_CODES = [
    {"codes": ["AC_100100", "AC_100110", "AC_100120", "AC_100010"], "username": "vben"},
    {"codes": ["AC_100010", "AC_100020", "AC_100030"], "username": "admin"},
    {"codes": ["AC_1000001", "AC_1000002"], "username": "jack"},
]


MOCK_MENUS = [
    {
        "username": "vben",
        "menus": ["menu1", "menu2"]
    },
    {
        "username": "admin",
        "menus": ["menu3", "menu4"]
    },
    {
        "username": "jack", 
        "menus": ["menu5", "menu6"]
    }
]

# Helper methods for JWT
def generate_token(user, secret, expiration):
    return jwt.encode({"username": user["username"], "exp": datetime.datetime.utcnow() + expiration},
                      secret, algorithm="HS256")


def verify_token(token, secret):
    try:
        data = jwt.decode(token, secret, algorithms=["HS256"])
        user = next((u for u in MOCK_USERS if u["username"] == data["username"]), None)
        return user
    except:
        return None


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"message": "Token is missing!"}), 401

        try:
            token = token.split(" ")[1]
            current_user = verify_token(token, app.config['SECRET_KEY'])
            if not current_user:
                raise Exception()
        except:
            return jsonify({"message": "Token is invalid!"}), 401

        return f(current_user, *args, **kwargs)

    return decorated


# 路由和视图函数
@app.route('/')
def index():
    return '''
    <h1>Hello Vben Admin Python Flask </h1>
    <h2>Mock service is starting</h2>
    <ul>
    <li><a href="/api/user/info">/api/user/info</a></li>
    <li><a href="/api/menu/all">/api/menu/all</a></li>
    <li><a href="/api/auth/codes">/api/auth/codes</a></li>
    <li><a href="/api/auth/login">/api/auth/login</a></li>
    </ul>
    ''', 200


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    user = next((u for u in MOCK_USERS if u["username"] == username and u["password"] == password), None)
    if not user:
        return jsonify({"error": "Username or password is incorrect."}), 403

    access_token = generate_token(user, app.config['SECRET_KEY'], datetime.timedelta(days=7))
    refresh_token = generate_token(user, app.config['REFRESH_SECRET_KEY'], datetime.timedelta(days=30))

    response_data = {
        "code": 0,
        "data": {**user, "accessToken": access_token},
        "error": None,
        "message": "ok"
    }

    resp = make_response(jsonify(response_data))
    resp.set_cookie('jwt', refresh_token, httponly=True, max_age=30 * 24 * 60 * 60, secure=True, samesite='None')
    return resp


@app.route('/api/auth/codes')
@token_required
def auth_codes(current_user):
    codes = next((c["codes"] for c in MOCK_CODES if c["username"] == current_user["username"]), [])
    response_data = {
        "code": 0,
        "data": codes,
        "error": None,
        "message": "ok"
    }
    return jsonify(response_data)


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    resp = make_response(jsonify({
        "code": 0,
        "data": None,
        "error": None,
        "message": "Successfully logged out"
    }))
    resp.delete_cookie('jwt')
    return resp


@app.route('/api/auth/refresh', methods=['POST'])
def refresh():
    refresh_token = request.cookies.get('jwt')
    if not refresh_token:
        return jsonify({"error": "Refresh token is missing"}), 403

    user = verify_token(refresh_token, app.config['REFRESH_SECRET_KEY'])
    if not user:
        return jsonify({"error": "Invalid refresh token"}), 403

    access_token = generate_token(user, app.config['SECRET_KEY'], datetime.timedelta(days=7))
    resp = make_response(jsonify({
        "code": 0,
        "data": {"accessToken": access_token},
        "error": None,
        "message": "ok"
    }))
    return resp


@app.route('/api/user/info')
@token_required
def user_info(current_user):
    user_data = {
        "id": current_user["id"],
        "realName": current_user["realName"],
        "roles": current_user["roles"],
        "username": current_user["username"]
    }
    return jsonify({
        "code": 0,
        "data": user_data,
        "error": None,
        "message": "ok"
    })


@app.route('/api/menu/all')
@token_required
def menu_all(current_user):
    menus = next((m["menus"] for m in MOCK_MENUS if m["username"] == current_user["username"]), [])
    return jsonify(menus)


# 启动应用
if __name__ == '__main__':
    app.run(port=5320, debug=True)