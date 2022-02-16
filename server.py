import hashlib
import hmac
import json
from typing import Optional

import base64

from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response

app = FastAPI()
SECRET_KEY = "d6cd058c2a0c444f984010e4c7076da9253c871a6f84b4c1448ebfafc8b49770"
PASSWORD_SALT = "1ad25a1b7bf3c76bc942699d4b27d6ed08e383a75de66a289dfbdbc9dfefa836"

def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256( (password + PASSWORD_SALT).encode() ).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return password_hash == stored_password_hash

users = {
    "viktor@user.com": {
        "name": "Виктор",
        "password": "6e8317f8c5a0337f599c88c4783cacaf435005f7b99e5cac669ea0720d217471",
        "balance": 100000
    },
    "ivan@user.com": {
        "name": "Иван",
        "password": "f0e97abec403613c89db647672bcf3e9c40396c94f4a47c6192cfd3844b15d9f",
        "balance": 555.55
    }
}


@app.get("/")
def index_page(username: Optional[str]=Cookie(default=None)):
    with open("templates/login.html", "r") as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(f"Привет, {users[valid_username]['name']}!<br />"
                    f"Баланс: {users[valid_username]['balance']}",
                     media_type="text/html")
    


@app.post("/login")
def process_login_page(data: dict = Body(...)):
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я вас не знаю!"
            }),
            media_type="aplication/json")

    response = Response(
        json.dumps({
           "success": True,
           "message": f"Привет {user['name']}!<br />Ваш баланс {user['balance']}" 
        }),
        media_type='aplication/json')

    username_signed = base64.b64encode(username.encode()).decode() + "." + sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response