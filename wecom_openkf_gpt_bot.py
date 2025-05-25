
import os
import sys
import logging
import requests
from flask import Flask, request, make_response
from wechatpy.enterprise.crypto import WeChatCrypto
from wechatpy.enterprise import WeChatClient
from wechatpy import parse_message
from wechatpy.messages import TextMessage
import openai

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
SECRET = os.getenv("SECRET")
OPEN_KFID = os.getenv("OPEN_KFID")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").replace("\n", "").strip()

openai.api_key = OPENAI_API_KEY
crypto = WeChatCrypto(TOKEN, ENCODING_AES_KEY, CORPID)
client = WeChatClient(CORPID, SECRET)
app = Flask(__name__)

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
        logging.error("❌ GPT 请求失败: %s", str(e))
        return "很抱歉，系统繁忙，请稍后再试。"

@app.route("/wechat_kf_callback", methods=["GET", "POST"])
def wechat_kf_callback():
    logging.info("📥 收到微信客服平台消息")

    if request.method == "GET":
        try:
            msg_signature = request.args.get("msg_signature")
            timestamp = request.args.get("timestamp")
            nonce = request.args.get("nonce")
            echostr = request.args.get("echostr")
            if not echostr:
                return "pong", 200
            echo = crypto.check_signature(msg_signature, timestamp, nonce, echostr)
            return make_response(echo)
        except Exception as e:
            logging.error("❌ URL 验证失败: %s", str(e))
            return "fail", 500

    if request.method == "POST":
        try:
            msg_signature = request.args.get("msg_signature")
            timestamp = request.args.get("timestamp")
            nonce = request.args.get("nonce")
            xml = request.data
            logging.info("📦 接收到加密 XML: %s", xml.decode("utf-8"))

            decrypted = crypto.decrypt_message(xml, msg_signature, timestamp, nonce)
            msg = parse_message(decrypted)
            logging.info("💬 消息类型: %s", type(msg).__name__)
            user_id = msg.source

            if isinstance(msg, TextMessage):
                user_text = msg.content.strip()
                logging.info("💬 用户 [%s] 发来: %s", user_id, user_text)

                reply_text = query_product_price(user_text)
                if not reply_text:
                    reply_text = query_with_gpt(user_text)

                client.kf_message.send_text({
                    "touser": user_id,
                    "open_kfid": OPEN_KFID,
                    "msgtype": "text",
                    "text": {"content": reply_text}
                })
            else:
                logging.warning("⚠️ 非文本消息，类型为 %s，跳过处理", type(msg).__name__)

            return "success", 200
        except Exception as e:
            logging.error("❌ 消息处理失败: %s", str(e))
            return "fail", 500

    return "ok", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
