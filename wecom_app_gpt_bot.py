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
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

openai = OpenAI(api_key=OPENAI_API_KEY)

crypto = WeChatCrypto(TOKEN, ENCODING_AES_KEY, CORPID)
app = Flask(__name__)

# 示例商品清单（你可以替换为真实数据）
PRODUCTS = {
    "菠菜": "$5 / 2磅",
    "土豆": "$8 / 1袋",
    "玉米": "$9 / 4根",
    "素食鸡": "$20 / 1只",
    "鸡蛋": "$13 / 1打"
}


def query_product_price(query):
    for name, price in PRODUCTS.items():
        if name in query:
            return f"{name} 的价格是 {price}"
    return None


def query_with_gpt(user_input):
    prompt = f"我有以下果蔬商品价格清单：\n" + "\n".join([f"{k}: {v}" for k, v in PRODUCTS.items()]) + \
             f"\n请根据这个清单回答用户问题：\n用户：{user_input}\n回复："
    try:
        chat_completion = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "user", "content": prompt}
            ],
            temperature=0.4,
            max_tokens=100
        )
        return chat_completion.choices[0].message.content.strip()
    except Exception as e:
        logging.error("❌ GPT 请求失败: %s", str(e))
        return "当前查询人数过多，请稍后再试。"


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

            # 优先查询本地商品
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
