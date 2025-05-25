
import os
import json
import time
import hashlib
import traceback
from flask import Flask, request
from dotenv import load_dotenv
from wechatpy.enterprise.crypto import WeChatCrypto
from wechatpy.client import WeChatClient
import requests
import xmltodict

print("💡 当前使用的 CORPID:", os.getenv("CORPID"))
print("💡 当前使用的 SECRET:", os.getenv("SECRET"))

load_dotenv()

TOKEN = os.getenv("TOKEN")
ENCODING_AES_KEY = os.getenv("ENCODING_AES_KEY")
CORPID = os.getenv("CORPID")
SECRET = os.getenv("SECRET")
OPEN_KFID = os.getenv("OPEN_KFID")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

app = Flask(__name__)
crypto = WeChatCrypto(TOKEN, ENCODING_AES_KEY, CORPID)
client = WeChatClient(CORPID, SECRET)

# 消息缓存避免重复回答
message_cache = {}

def get_cached_response(user_id, content):
    key = f"{user_id}:{hashlib.md5(content.encode()).hexdigest()}"
    entry = message_cache.get(key)
    if entry and time.time() - entry["timestamp"] < 300:
        return entry["reply"]
    return None

def cache_response(user_id, content, reply):
    key = f"{user_id}:{hashlib.md5(content.encode()).hexdigest()}"
    message_cache[key] = {"reply": reply, "timestamp": time.time()}

def ask_gpt(question):
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "gpt-3.5-turbo",
        "temperature": 0.3,
        "messages": [
            {
                "role": "system",
                "content": """
你是一个中文果蔬商店的智能客服，以下是你售卖的商品清单（价格为单位售价）：
- 菠菜: $5 / 2磅
- 土豆: $8 / 1袋
- 玉米: $9 / 4根
- 素食鸡: $20 / 1只
- 鸡蛋: $13 / 1打

你的职责：
1. 回答用户关于价格、购买方式、产品数量等问题。
2. 遇到模糊提问（如“你们卖什么”、“怎么买”）要主动介绍商品和服务。
3. 遇到打招呼（如“你好”、“在吗”）仅回复一次问候语“你好，请问有什么可以帮助您的呢？”，不要重复发送。
4. 如果用户提到未列出的商品，回复“目前没有此商品”，并推荐已有商品。
5. 回复请简洁明了，直接说结果，避免多余寒暄。
"""
            },
            {"role": "user", "content": question}
        ]
    }
    response = requests.post(url, headers=headers, json=data)
    return response.json()["choices"][0]["message"]["content"]

@app.route("/wechat_kf_callback", methods=["GET", "POST"])
def wechat_kf():
    if request.method == "GET":
        msg_signature = request.args.get("msg_signature")
        timestamp = request.args.get("timestamp")
        nonce = request.args.get("nonce")
        echostr = request.args.get("echostr")
        if crypto.check_signature(msg_signature, timestamp, nonce):
            return crypto.decrypt(echostr)
        else:
            return "invalid signature", 403

    try:
        msg_signature = request.args["msg_signature"]
        timestamp = request.args["timestamp"]
        nonce = request.args["nonce"]
        encrypted_xml = request.data
        msg = crypto.decrypt_message(encrypted_xml, msg_signature, timestamp, nonce)
        msg_json = xml_to_json(msg)
        from_user = msg_json.get("FromUserName")
        print("📥 解密成功 XML -> JSON:", msg_json)

        if msg_json.get("MsgType") == "event" and msg_json.get("Event") == "kf_msg_or_event":
            fetch_and_respond(from_user)
        return "success"
    except Exception as e:
        print("❌ 回调处理失败:")
        traceback.print_exc()
        return "error", 500

def fetch_and_respond(openid):
    try:
        res = client.get("/cgi-bin/kf/sync_msg", params={"cursor": "", "token": client.access_token})
        for msg in res.get("msg_list", []):
            if msg.get("msgtype") != "text" or "text" not in msg:
                continue
            content = msg["text"]["content"]
            cached = get_cached_response(openid, content)
            if cached:
                print("⚠️ 忽略重复内容")
                return
            print("💬 收到内容:", content)
            reply = ask_gpt(content)
            print("📤 回复内容:", reply)
            cache_response(openid, content, reply)
            client.post("/cgi-bin/kf/send_msg", data=json.dumps({
                "touser": openid,
                "msgtype": "text",
                "text": {"content": reply},
                "open_kfid": OPEN_KFID
            }))
    except Exception as e:
        print("❌ 拉取处理消息失败:")
        traceback.print_exc()

def xml_to_json(xml_str):
    return json.loads(json.dumps(xmltodict.parse(xml_str)["xml"]))

if __name__ == "__main__":
    try:
        ip = requests.get("https://api.ipify.org").text
        print("🌍 当前公网 IP:", ip)
    except:
        pass
    app.run(host="0.0.0.0", port=10000, debug=True)
