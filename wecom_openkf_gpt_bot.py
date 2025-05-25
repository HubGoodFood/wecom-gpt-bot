
import os
import sys
import logging
import requests
from flask import Flask, request, make_response
from wechatpy.enterprise.crypto import WeChatCrypto
import xml.etree.ElementTree as ET
from openai import OpenAI

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

try:
    ip = requests.get("https://api.ipify.org").text
    logging.info("🌍 当前公网 IP: %s", ip)
except:
    pass

TOKEN = os.getenv("TOKEN")
ENCODING_AES_KEY = os.getenv("ENCODING_AES_KEY")
CORPID = os.getenv("CORPID")
SECRET = os.getenv("SECRET")
OPEN_KFID = os.getenv("OPEN_KFID")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

app = Flask(__name__)
crypto = WeChatCrypto(TOKEN, ENCODING_AES_KEY, CORPID)
openai_client = OpenAI(api_key=OPENAI_API_KEY)

PRODUCTS = {
    "菠菜": {"price": 5, "unit": "2磅"},
    "土豆": {"price": 8, "unit": "1袋"},
    "玉米": {"price": 9, "unit": "4根"},
    "素食鸡": {"price": 20, "unit": "1只"},
    "鸡蛋": {"price": 13, "unit": "1打"},
}

last_user_messages = {}

def get_access_token():
    r = requests.get("https://qyapi.weixin.qq.com/cgi-bin/gettoken", params={
        "corpid": CORPID,
        "corpsecret": SECRET
    })
    return r.json().get("access_token", "")

def extract_token(xml_str):
    try:
        return ET.fromstring(xml_str).find("Token").text
    except:
        return ""

def pull_latest_text(open_kfid, token):
    access_token = get_access_token()
    url = f"https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token={access_token}"
    cursor = ""
    while True:
        payload = {"cursor": cursor, "token": token, "limit": 10}
        r = requests.post(url, json=payload)
        data = r.json()
        for msg in data.get("msg_list", []):
            if msg["msgtype"] == "text" and msg["open_kfid"] == open_kfid:
                return msg["external_userid"], msg["text"]["content"]
        if not data.get("has_more"): break
        cursor = data.get("next_cursor", "")
    return None, None

def send_text_msg(user_id, content):
    access_token = get_access_token()
    url = f"https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg?access_token={access_token}"
    payload = {
        "touser": user_id,
        "open_kfid": OPEN_KFID,
        "msgtype": "text",
        "text": {"content": content}
    }
    res = requests.post(url, json=payload)
    logging.info("📤 微信发送结果: %s", res.json())
    if res.json().get("errcode") == 95001:
        logging.warning("❗️发送失败：接口频率限制")

def query_with_gpt(user_input):
    product_list = "\n".join([f"- {k}: ${v['price']} / {v['unit']}" for k, v in PRODUCTS.items()])
    prompt = f"""
你是一个中文果蔬商店的智能客服，以下是你售卖的商品清单（价格为单位售价）：
{product_list}

你的职责：
1. 回答用户关于价格、购买方式、产品数量等问题。
2. 遇到模糊提问（如“你们卖什么”、“怎么买”）要主动介绍商品和服务。
3. 遇到打招呼（如“你好”、“在吗”）仅回复一次问候语“你好，请问有什么可以帮助您的呢？”，不要重复发送。
4. 如果用户提到未列出的商品，回复“目前没有此商品”，并推荐已有商品。
5. 回复请简洁明了，直接说结果，避免多余寒暄。
"""
    try:
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": user_input}
            ],
            temperature=0.3
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logging.error("❌ GPT 错误: %s", str(e))
        return "系统繁忙，请稍后再试。"

@app.route("/wechat_kf_callback", methods=["GET", "POST"])
def callback():
    if request.method == "GET":
        try:
            msg_signature = request.args.get("msg_signature")
            timestamp = request.args.get("timestamp")
            nonce = request.args.get("nonce")
            echostr = request.args.get("echostr")
            echo = crypto.check_signature(msg_signature, timestamp, nonce, echostr)
            return make_response(echo)
        except Exception as e:
            logging.error("URL 验证失败: %s", str(e))
            return "fail", 500

    if request.method == "POST":
        try:
            msg_signature = request.args.get("msg_signature")
            timestamp = request.args.get("timestamp")
            nonce = request.args.get("nonce")
            encrypted_xml = request.data
            decrypted = crypto.decrypt_message(encrypted_xml, msg_signature, timestamp, nonce)
            token = extract_token(decrypted)
            user_id, content = pull_latest_text(OPEN_KFID, token)

            if not user_id or not content:
                return "ok", 200

            # 去重判断
            if last_user_messages.get(user_id) == content:
                logging.info("⚠️ 忽略重复内容")
                return "ok", 200
            last_user_messages[user_id] = content

            reply = query_with_gpt(content)
            send_text_msg(user_id, reply)
            return "ok", 200
        except Exception as e:
            logging.error("❌ 回调处理失败: %s", str(e))
            return "fail", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
