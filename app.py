# server.py
import os
import json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, make_response, send_from_directory
import jwt
import requests

from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

PORT = int(os.getenv("PORT", 8080))
SECRET = os.getenv("SECRET")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
VARIATION = os.getenv("VARIATION")
IS_PRODUCTION = os.getenv("NODE_ENV") == "production"

if not SECRET:
    print("⚠️ 環境変数 SECRET が設定されていません！")
if not DISCORD_WEBHOOK_URL:
    print("⚠️ 環境変数 DISCORD_WEBHOOK_URL が設定されていません！")
if not VARIATION:
    print("⚠️ 環境変数 VARIATION が設定されていません！")

print("=========================")
print(" ")
print("Copyright (C) 2025 @kiyu4776")
print("This file is proprietary and confidential.")
print("Unauthorized reproduction or distribution is prohibited.")
print(" ")
print(f"Var : {VARIATION}")
print(" ")
print("==========log============")

# data.json からキー読み込み
KEYS = []
try:
    with open("data/data.json", "r", encoding="utf-8") as f:
        data = json.load(f)
        if isinstance(data.get("key"), list) and data["key"]:
            KEYS = data["key"]
        elif isinstance(data.get("key"), str) and data["key"].strip():
            KEYS = [data["key"]]
        else:
            print("data.json の key が未定義または空です。")
    print("キーが正常に読み込まれました")
except Exception as e:
    print("キー読み込み失敗:", e)
    exit(1)

# Helper: Discord Webhook
def send_webhook(message: str):
    payload = {"content": f"```{message}```"}
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload)
    except Exception as e:
        print("Webhook送信エラー:", e)

# API: /api/check-key
@app.route("/api/check-key", methods=["POST"])
def check_key():
    data = request.get_json()
    user_key = data.get("key")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "")
    time = datetime.utcnow().isoformat()

    # Discord通知
    send_webhook(f"パスワードが送信されました:\n日付: {time}\nIP: {ip}\nデバイス: {user_agent}\n入力キー: {user_key}")

    if user_key in KEYS:
        token = jwt.encode(
            {"access": True, "exp": datetime.utcnow() + timedelta(minutes=1)},
            SECRET,
            algorithm="HS256"
        )
        resp = make_response(jsonify({"ok": True}))
        resp.set_cookie(
            "TOKEN",
            token,
            httponly=True,
            secure=True,
            max_age=60,
            samesite="Strict"
        )
        return resp
    else:
        return jsonify({"ok": False}), 401

# Script.html 配信
@app.route("/Script.html", methods=["GET"])
def script_html():
    token = request.cookies.get("TOKEN")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    user_agent = request.headers.get("User-Agent", "")
    time = datetime.utcnow().isoformat()

    if not token:
        send_webhook(f"❌️不正なログイン:認証トークンが見つかりません\n日付: {time}\nIP: {ip}\nデバイス: {user_agent}")
        return "No token provided", 401

    try:
        decoded = jwt.decode(token, SECRET, algorithms=["HS256"])
        if not decoded.get("access"):
            raise jwt.InvalidTokenError("access False")
    except Exception as e:
        send_webhook(f"❌️不正なログイン:無効なトークン\n日付: {time}\nIP: {ip}\nデバイス: {user_agent}\n理由: {e}")
        return "Invalid or expired token", 403

    send_webhook(f"✅ 正常アクセス\n日付: {time}\nIP: {ip}\nデバイス: {user_agent}")
    return send_from_directory("private", "Script.html", cache_timeout=0)

if __name__ == "__main__":
    print(f"✅ サーバー起動: http://localhost:{PORT}")
    app.run(host="0.0.0.0", port=PORT)
