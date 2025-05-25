import os
import hashlib
import time
import xmltodict
import requests
from flask import Flask, request, abort
from wechatpy.enterprise.crypto import WeChatCrypto
from dotenv import load_dotenv

# 加载 .env 环境变量
load_dotenv()

# 获取必要配置
TOKEN = os.getenv("TOKEN")
ENCODING_AES_KEY = os.getenv("ENCODING_AES_KEY")
CORPID = os.getenv("CORPID")
OPEN_KFID = os.getenv("OPEN_KFID")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
SECRET = os.getenv("SECRET")

app = Flask(__name__)
crypto = WeChatCrypto(TOKEN, ENCODING_AES_KEY, CORPID)

cache = {}

# 构造商品说明 prompt
SYSTEM_PROMPT = """你是一个中文果蔬商店的智能客服，以下是你售卖的商品清单（价格为单位售价）：
土豆：$8/袋
菠菜：$4/把
玉米：$5/根
素食鸡：$12/包
鸡蛋：$6/盒

请根据用户提问用简洁中文作答，例如他们问‘我要两袋土豆’，你应该回答‘好的，两袋土豆一共是$16。请问您还需要购买其他商品吗？’。你不需要自我介绍或道谢，直接回复关键信息。
"""

def ask_gpt(user_id, user_message):
    key = user_id + hashlib.md5(user_message.encode()).hexdigest()
    if key in cache and time.time() - cache[key]["time"] < 60:
        print("🤖 使用缓存回复:", cache[key]["answer"])
        return cache[key]["answer"]

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_message}
    ]
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "gpt-3.5-turbo",
        "messages": messages
    }

    response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
    answer = response.json()["choices"][0]["message"]["content"]
    print("🤖 GPT 回复:", answer)
    cache[key] = {"answer": answer, "time": time.time()}
    return answer

@app.route("/wechat_kf_callback", methods=["GET", "POST"])

def wechat_kf():
    if request.method == "GET":
        msg_signature = request.args.get("msg_signature")
        timestamp = request.args.get("timestamp")
        nonce = request.args.get("nonce")
        echostr = request.args.get("echostr")

        if not all([msg_signature, timestamp, nonce, echostr]):
            return "Missing parameters", 400

        try:
            decrypted_str = crypto.verify_url(msg_signature, timestamp, nonce, echostr)
            return decrypted_str
        except Exception as e:
            print(f"URL 验证失败: {e}")
            return "Verification failed", 403

    # 原 POST 逻辑保留
sg = crypto.decrypt_message(encrypted_xml, msg_signature, timestamp, nonce)
        msg_dict = xmltodict.parse(msg)
        msg_json = msg_dict["xml"]

        if msg_json.get("MsgType") == "event" and msg_json.get("Event") == "kf_msg_or_event":
            fetch_and_respond(msg_json.get("FromUserName"))
    except Exception as e:
        print("❌ 回调处理失败:", e)
        return "error", 500

    return "success"

def fetch_and_respond(openid):
    access_token_resp = requests.get(
        "https://qyapi.weixin.qq.com/cgi-bin/gettoken",
        params={"corpid": CORPID, "corpsecret": SECRET}
    ).json()

    if "access_token" not in access_token_resp:
        raise Exception(f"❌ 获取 access_token 失败: {access_token_resp}")
    access_token = access_token_resp["access_token"]
    print("✅ 获取 access_token 成功")

    res = requests.post(
        "https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg",
        params={"access_token": access_token},
        json={"cursor": "", "token": access_token, "open_kfid": OPEN_KFID}
    ).json()

    if res.get("errcode") != 0:
        raise Exception(f"❌ 拉取消息失败: {res}")

    print("📥 收到消息列表:", res["msg_list"])

    for item in res["msg_list"]:
        if item.get("msgtype") != "text":
            continue

        content = item["text"]["content"]
        external_userid = item["external_userid"]
        reply_text = ask_gpt(external_userid, content)

        send_res = requests.post(
            "https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg",
            params={"access_token": access_token},
            json={
                "touser": external_userid,
                "open_kfid": OPEN_KFID,
                "msgtype": "text",
                "text": {"content": reply_text}
            }
        ).json()
        print("📤 微信发送结果:", send_res)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
