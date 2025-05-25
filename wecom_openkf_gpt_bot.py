import os
import json
import logging
from flask import Flask, request, abort
from wechatpy.utils import check_signature
from wechatpy.enterprise.crypto import WeChatCrypto
from wechatpy.client import WeChatClient
from wechatpy.exceptions import WeChatClientException
from openai import OpenAI

# ==== 环境变量 ====
CORPID = os.getenv("CORPID")
SECRET = os.getenv("SECRET")
TOKEN = os.getenv("TOKEN")
AES_KEY = os.getenv("ENCODING_AES_KEY")
OPEN_KFID = os.getenv("OPEN_KFID")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
openai_client = OpenAI(api_key=OPENAI_API_KEY)

# ==== 初始化 ====
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
client = WeChatClient(CORPID, SECRET)
crypto = WeChatCrypto(TOKEN, AES_KEY, CORPID)

# ==== Flask 应用 ====
app = Flask(__name__)

@app.route("/wechat_kf_callback", methods=["GET", "POST"])
def wechat_kf_callback():
    if request.method == "GET":
        # 微信服务器验证 URL
        msg_signature = request.args.get("msg_signature")
        timestamp = request.args.get("timestamp")
        nonce = request.args.get("nonce")
        echostr = request.args.get("echostr")
        try:
            echo = crypto.check_signature(msg_signature, timestamp, nonce, echostr)
            return echo
        except Exception as e:
            logger.error(f"验证失败: {e}")
            abort(403)

    # POST: 接收消息
    msg_signature = request.args.get("msg_signature")
    timestamp = request.args.get("timestamp")
    nonce = request.args.get("nonce")

    raw_xml = request.data
    try:
        decrypted_xml = crypto.decrypt_message(encrypt, signature, timestamp, nonce)
        logger.info(f"📥 解密后 XML: {decrypted_xml}")
    
        # 解析 XML 字符串为字典
        msg_dict = xmltodict.parse(decrypted_xml)
        msg_json = msg_dict["xml"]
    
        # 获取 open_kfid
        open_kfid = msg_json.get("OpenKfId")
    
        # 拉取消息并回复
        fetch_and_respond(open_kfid)
    
    except Exception as e:
        logger.error(f"❌ 回调处理失败: {e}")
        abort(500)

    return "success"

def fetch_and_respond(open_kfid):
    access_token = client.access_token
    url = f"https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token={access_token}"
    payload = {
        "cursor": "",
        "token": access_token,
        "open_kfid": open_kfid,
    }
    res = client.session.post(url, data=json.dumps(payload))
    res_json = res.json()
    logger.info(f"🧾 拉取消息响应: {res_json}")

    msg_list = res_json.get("msg_list", [])
    for msg in msg_list:
        if msg.get("msgtype") == "text":
            external_userid = msg.get("external_userid")
            user_msg = msg["text"]["content"]
            logger.info(f"💬 用户 [{external_userid}] 发来: {user_msg}")

            # 调用 OpenAI 回复
            reply = ask_gpt(user_msg)
            send_msg(open_kfid, external_userid, reply)

def ask_gpt(query):
    messages = [
        {"role": "system", "content": "你是一个中文果蔬商店的智能客服，以下是你售卖的商品清单（价格为单位售价）：\n- 菠菜: $5 / 2磅\n- 土豆: $8 / 1袋\n- 玉米: $9 / 4根\n- 素食鸡: $20 / 1只\n- 鸡蛋: $13 / 1打\n\n你的职责：\n1. 回答用户关于价格、购买方式、产品数量等问题。\n2. 遇到模糊提问（如“你们卖什么”、“怎么买”）要主动介绍商品和服务。\n3. 遇到打招呼（如“你好”、“在吗”）仅回复一次问候语“你好，请问有什么可以帮助您的呢？”，不要重复发送。\n4. 如果用户提到未列出的商品，回复“目前没有此商品”，并推荐已有商品。\n5. 回复请简洁明了，直接说结果，避免多余寒暄。"},
        {"role": "user", "content": query}
    ]
    response = openai_client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=messages,
        temperature=0.3,
    )
    return response.choices[0].message.content

def send_msg(open_kfid, external_userid, content):
    access_token = client.access_token
    url = f"https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg?access_token={access_token}"
    payload = {
        "touser": external_userid,
        "open_kfid": open_kfid,
        "msgtype": "text",
        "text": {
            "content": content
        }
    }
    res = client.session.post(url, data=json.dumps(payload, ensure_ascii=False).encode('utf-8'))
    logger.info(f"📤 微信发送结果: {res.json()}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
