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

ENHANCED_PROMPT = (
    "你是一个智能果蔬客服助手，负责回答用户关于商品价格的问题。\n"
    "你拥有以下商品清单（价格为单位售价）：\n"
    + "\n".join([f"- {k}: {v}" for k, v in PRODUCTS.items()])
    + "\n你的目标：\n"
    "1. 识别用户是否询问单个商品价格，如果是，就直接回复该商品价格。\n"
    "2. 识别用户是否在询问多个商品总价，提取每个商品及数量，并计算总价。\n"
    "3. 支持灵活单位表达，包括：斤、磅、袋、根、个、打、只 等混合单位；识别中文数字（如“两袋”）。\n"
    "4. 用户提到未在清单中的商品，要礼貌回复“目前没有此商品”，并列出可选商品。\n"
    "5. 回复要简洁自然，有亲和力，不要生硬复制清单内容。\n"
    "\n举例：\n"
    "用户：“我想买4磅菠菜、3袋土豆和5只素食鸡，一共多少钱？”\n"
    "回复：“4磅菠菜（$10）+ 3袋土豆（$24）+ 5只素食鸡（$100），总共是 $134。”\n"
    "\n请根据以上要求处理用户的问题。"
)

def query_product_price(query):
    for name, price in PRODUCTS.items():
        if name in query:
            return f"{name} 的价格是 {price}"
    return None

def query_with_gpt(user_input):
    try:
        chat_completion = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": ENHANCED_PROMPT},
                {"role": "user", "content": user_input}
            ],
            temperature=0.4,
            max_tokens=150
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
