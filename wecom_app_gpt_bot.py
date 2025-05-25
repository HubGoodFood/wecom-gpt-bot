import os
import sys
import logging
import requests
from flask import Flask, request, make_response
from wechatpy.enterprise.crypto import WeChatCrypto
from wechatpy.utils import to_text
from wechatpy import parse_message
from wechatpy.replies import create_reply
from openai import OpenAI

# 配置日志
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logging.debug("🔑 API key prefix: %s", OPENAI_API_KEY[:10])
logging.debug("🔑 API key length: %d", len(OPENAI_API_KEY))

# 显示公网 IP
try:
    public_ip = requests.get("https://api.ipify.org").text
    logging.info("\U0001F310 当前服务器公网 IP: %s", public_ip)
except Exception as e:
    logging.error("❌ 获取公网 IP 失败: %s", str(e))

# 读取配置
TOKEN = os.getenv("TOKEN")
ENCODING_AES_KEY = os.getenv("ENCODING_AES_KEY")
CORPID = os.getenv("CORPID")
AGENT_ID = os.getenv("AGENT_ID")
AGENT_SECRET = os.getenv("AGENT_SECRET")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").replace("\\n", "").strip()

openai = OpenAI(api_key=OPENAI_API_KEY)

crypto = WeChatCrypto(TOKEN, ENCODING_AES_KEY, CORPID)
app = Flask(__name__)

# 商品清单
PRODUCTS = {
    "菠菜": {"price": 5, "unit": "2磅"},
    "土豆": {"price": 8, "unit": "1袋"},
    "玉米": {"price": 9, "unit": "4根"},
    "素食鸡": {"price": 20, "unit": "1只"},
    "鸡蛋": {"price": 13, "unit": "1打"},
}


def query_product_price(query):
    for name, item in PRODUCTS.items():
        if name in query:
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
"""

    try:
        response = openai.chat.completions.create(
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
        logging.error("❌ GPT 请求失败: %s", str(e))
        return "很抱歉，系统繁忙，请稍后再试。"


@app.route("/", methods=["GET", "POST", "HEAD"])
def wechat_callback():
    logging.info("🚨 wechat_callback 被触发")
    logging.info("🔍 method: %s", request.method)

    if request.method == "GET":
        try:
            msg_signature = request.args.get("msg_signature")
            timestamp = request.args.get("timestamp")
            nonce = request.args.get("nonce")
            echostr = request.args.get("echostr")
            if not echostr:
                return "pong", 200
            echo = crypto.decrypt_message(echostr, msg_signature, timestamp, nonce)
            return make_response(echo)
        except Exception as e:
            logging.error("❌ 验证 URL 异常: %s", str(e))
            return "fail", 500

    if request.method == "POST":
        try:
            msg_signature = request.args.get("msg_signature")
            timestamp = request.args.get("timestamp")
            nonce = request.args.get("nonce")
            xml = request.data
            logging.info("📦 原始 XML: %s", xml.decode("utf-8"))

            msg = crypto.decrypt_message(xml, msg_signature, timestamp, nonce)
            logging.info("📖 解密后 XML: %s", msg)
            parsed = parse_message(msg)
            logging.info("🧾 用户发来内容: %s", parsed.content)

            user_query = parsed.content.strip()
            reply_text = query_product_price(user_query)
            if not reply_text:
                reply_text = query_with_gpt(user_query)

            reply_xml = create_reply(reply_text, message=parsed)
            encrypted = crypto.encrypt_message(to_text(reply_xml), nonce, timestamp)
            return make_response(encrypted)
        except Exception as e:
            logging.error("❌ 解密或回复异常: %s", str(e))
            return "fail", 500

    return "OK", 200


if __name__ == "__main__":
    print("✅ 启动完整客服版本 Flask 成功")
    app.run(host="0.0.0.0", port=10000)
