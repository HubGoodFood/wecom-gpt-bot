
import os
import json
import time
import hmac
import hashlib
import logging
import requests
from flask import Flask, request, abort
from wechatpy.crypto import WeChatCrypto
from wechatpy.utils import check_signature
from wechatpy.exceptions import InvalidSignatureException
from openai import OpenAI
from collections import deque
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

CORPID = os.getenv("CORPID")
SECRET = os.getenv("SECRET")
TOKEN = os.getenv("TOKEN")
ENCODING_AES_KEY = os.getenv("ENCODING_AES_KEY")
OPEN_KFID = os.getenv("OPEN_KFID")
client = OpenAI()

crypto = WeChatCrypto(TOKEN, ENCODING_AES_KEY, CORPID)

last_user_messages = {}

def is_duplicate(user_id, content):
    # 疑问词优先放行
    if any(q in content for q in ["什么", "怎么买", "如何", "几块", "多少", "有没有", "在哪", "怎么联系", "送不送", "可不可以"]):
        return False
    if user_id not in last_user_messages:
        last_user_messages[user_id] = deque(maxlen=5)
        return False
    if content in last_user_messages[user_id]:
        return True
    return False

@app.route("/wechat_kf_callback", methods=["GET", "POST"])
def wechat_kf_callback():
    msg_signature = request.args.get("msg_signature")
    timestamp = request.args.get("timestamp")
    nonce = request.args.get("nonce")

    if request.method == "GET":
        echostr = request.args.get("echostr")
        try:
            echo_str = crypto.check_signature(
                msg_signature, timestamp, nonce, echostr
            )
            return echo_str
        except InvalidSignatureException:
            abort(403)

    raw_msg = request.data
    msg = crypto.decrypt_message(raw_msg, msg_signature, timestamp, nonce)
    msg_json = json.loads(msg)

    open_kfid = msg_json.get("OpenKfId")
    if msg_json.get("MsgType") == "event":
        token = msg_json.get("Token")
        return handle_kf_event(open_kfid, token)
    return "OK"

def handle_kf_event(open_kfid, token):
    access_token = get_access_token()
    resp = requests.post(
        f"https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token={access_token}",
        json={"cursor": "", "token": token, "limit": 20, "voice_format": 0},
    )
    data = resp.json()
    logging.info(f"🧾 拉取消息响应: {data}")
    for item in data.get("msg_list", []):
        if item.get("msgtype") != "text":
            continue
        user_id = item["external_userid"]
        content = item["text"]["content"].strip()

        if is_duplicate(user_id, content):
            logging.info("⚠️ 忽略重复内容")
            continue
        last_user_messages.setdefault(user_id, deque(maxlen=5)).append(content)

        logging.info(f"💬 用户 [{user_id}] 发来: {content}")
        reply = get_gpt_reply(content)
        send_text_message(user_id, open_kfid, reply)
    return "OK"

def get_access_token():
    resp = requests.get(
        f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={CORPID}&corpsecret={SECRET}"
    )
    return resp.json()["access_token"]

def get_gpt_reply(content):
    try:
        system_prompt = '''
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
        '''.strip()

        completion = client.chat.completions.create(
            model="gpt-3.5-turbo",
            temperature=0.3,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": content},
            ],
        )
        return completion.choices[0].message.content.strip()
    except Exception as e:
        logging.error(f"GPT 错误: {e}")
        return "抱歉，系统繁忙，请稍后再试。"

def send_text_message(userid, kfid, text):
    access_token = get_access_token()
    payload = {
        "touser": userid,
        "open_kfid": kfid,
        "msgtype": "text",
        "text": {"content": text},
    }
    resp = requests.post(
        f"https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg?access_token={access_token}",
        json=payload,
    )
    logging.info(f"📤 微信发送结果: {resp.json()}")

if __name__ == "__main__":
    import socket
    ip = requests.get("https://api.ipify.org").text
    logging.info(f"🌍 当前公网 IP: {ip}")
    app.run(host="0.0.0.0", port=10000)
