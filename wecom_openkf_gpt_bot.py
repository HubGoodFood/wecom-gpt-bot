
import os
import sys
import logging
import requests
from flask import Flask, request, make_response
from wechatpy.enterprise.crypto import WeChatCrypto
from wechatpy.enterprise import WeChatClient
from wechatpy import parse_message
import openai
import time

# 日志配置
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

# 公网 IP 显示
try:
    ip = requests.get("https://api.ipify.org").text
    logging.info("🌍 当前公网 IP: %s", ip)
except Exception as e:
    logging.warning("无法获取公网 IP: %s", str(e))

# 配置
TOKEN = os.getenv("TOKEN")
ENCODING_AES_KEY = os.getenv("ENCODING_AES_KEY")
CORPID = os.getenv("CORPID")
SECRET = os.getenv("SECRET")  # 企业微信 Secret
OPEN_KFID = os.getenv("OPEN_KFID")  # OpenKF 客服 ID
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").replace("\n", "").strip()

openai.api_key = OPENAI_API_KEY
crypto = WeChatCrypto(TOKEN, ENCODING_AES_KEY, CORPID)
client = WeChatClient(CORPID, SECRET)
app = Flask(__name__)

# 商品清单
PRODUCTS = {
    "菠菜": {"price": 5, "unit": "2磅"},
    "土豆": {"price": 8, "unit": "1袋"},
    "玉米": {"price": 9, "unit": "4根"},
    "素食鸡": {"price": 20, "unit": "1只"},
    "鸡蛋": {"price": 13, "unit": "1打"},
}
GPT_KEYWORDS = ["几", "多", "总共", "一共", "加起来", "多少", "需要", "要", "斤", "磅", "袋", "根", "个", "打"]

def should_use_gpt(query):
    count = sum(1 for name in PRODUCTS if name in query)
    return count > 1 or any(k in query for k in GPT_KEYWORDS)

def query_product_price(query):
    for name, item in PRODUCTS.items():
        if name in query and not should_use_gpt(query):
            return f"{name} 的价格是 ${item['price']} / {item['unit']}"
    return None

def query_with_gpt(user_input):
    product_list = "\n".join([f"- {k}: ${v['price']} / {v['unit']}" for k, v in PRODUCTS.items()])
    system_prompt = f"""
你是一个智能果蔬客服助手，负责回答用户关于商品价格的问题。

你拥有以下商品清单（价格为单位售价）：
{product_list}

你的目标：
1. 识别用户是否在查询单个商品价格，如果是，直接回复该商品价格。
2. 识别用户是否在询问多个商品的总价，提取每个商品及数量，并计算总价。
3. 支持灵活单位表达，包括：斤、磅、袋、根、个、打，能理解如“4磅菠菜”“两袋土豆”。
4. 用户提到未在清单中的商品，要回复“目前没有此商品”，并推荐已有商品。
5. 支持模糊提问，如“加起来多少钱”“一共多少钱”等。
6. 回复中应直接输出价格计算结果，简洁明了。
7. 识别中英文表达均可。
"""
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_input}
            ],
            temperature=0.3,
            max_tokens=300
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logging.error("GPT 错误: %s", str(e))
        return "系统繁忙，请稍后再试。"

def pull_latest_text_message(open_kfid):
    access_token = client.access_token
    url = f"https://qyapi.weixin.qq.com/cgi-bin/kf/msg/list?access_token={access_token}"
    now = int(time.time())
    payload = {
        "start_time": now - 60,
        "end_time": now,
        "open_kfid": open_kfid,
        "msgid": "",
        "number": 1
    }
    try:
        r = requests.post(url, json=payload)
        data = r.json()
        logging.info("🧾 拉取消息响应: %s", data)
        for msg in data.get("msg_list", []):
            if msg["msgtype"] == "text":
                return msg["external_userid"], msg["text"]["content"]
    except Exception as e:
        logging.error("❌ 拉取消息失败: %s", str(e))
    return None, None

@app.route("/wechat_kf_callback", methods=["GET", "POST"])
def wechat_kf_callback():
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
            decrypted_xml = crypto.decrypt_message(encrypted_xml, msg_signature, timestamp, nonce)
            logging.info("📥 解密后 XML: %s", decrypted_xml)

            if "kf_msg_or_event" in decrypted_xml:
                userid, text = pull_latest_text_message(OPEN_KFID)
                if userid and text:
                    logging.info("💬 用户 [%s] 发来: %s", userid, text)
                    reply = query_product_price(text) or query_with_gpt(text)
                    client.kf_message.send_text({
                        "touser": userid,
                        "open_kfid": OPEN_KFID,
                        "msgtype": "text",
                        "text": {"content": reply}
                    })
            return "success", 200
        except Exception as e:
            logging.error("❌ 回调处理失败: %s", str(e))
            return "fail", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
