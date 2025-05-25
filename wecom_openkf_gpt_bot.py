import os
import json
import time
import hashlib
import traceback
from flask import Flask, request
from dotenv import load_dotenv
from wechatpy.enterprise.crypto import WeChatCrypto
from wechatpy.client import WeChatClient
# from wechatpy.client.api import WeChatMessage # 此行导入的模块 WeChatMessage 未在代码中使用
import requests
import xmltodict # 添加缺失的导入
import openai # 添加缺失的导入 (fetch_and_respond 函数中使用)

load_dotenv()

TOKEN = os.getenv("TOKEN")
ENCODING_AES_KEY = os.getenv("ENCODING_AES_KEY")
CORPID = os.getenv("CORPID")
SECRET = os.getenv("SECRET")
OPEN_KFID = os.getenv("OPEN_KFID") # 您的企业微信客服ID
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# 如果 openai 库版本 >= 1.0.0， OpenAI API Key 通常会自动从环境变量 OPENAI_API_KEY 读取
# 或者您可能需要显式初始化:
# openai.api_key = OPENAI_API_KEY
# 或者使用新的客户端初始化方式：
# client_openai = openai.OpenAI(api_key=OPENAI_API_KEY)
# 然后在 fetch_and_respond 中使用 client_openai.chat.completions.create

app = Flask(__name__)
crypto = WeChatCrypto(TOKEN, ENCODING_AES_KEY, CORPID)
client = WeChatClient(CORPID, SECRET) # 此 client 实例未在后续代码中使用，请确认是否需要

# 消息缓存避免重复回答
message_cache = {}

def get_cached_response(user_id, content):
    key = f"{user_id}:{hashlib.md5(content.encode()).hexdigest()}"
    entry = message_cache.get(key)
    if entry and time.time() - entry["timestamp"] < 300: # 缓存有效期300秒
        return entry["reply"]
    return None

def cache_response(user_id, content, reply):
    key = f"{user_id}:{hashlib.md5(content.encode()).hexdigest()}"
    message_cache[key] = {"reply": reply, "timestamp": time.time()}

# ask_gpt 函数未在当前逻辑中被调用，但保留其定义
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

@app.route("/wechat_kf_callback", methods=["POST"])
def wechat_kf():
    try:
        msg_signature = request.args.get("msg_signature")
        timestamp = request.args.get("timestamp")
        nonce = request.args.get("nonce")
        encrypted_xml = request.data

        msg = crypto.decrypt_message(encrypted_xml, msg_signature, timestamp, nonce)
        msg_dict = xmltodict.parse(msg)
        msg_json = msg_dict["xml"]

        # FromUserName 是外部用户的 external_userid
        # ToUserName 通常是 CorpID 或者智能客服ID (如果消息是直接发给特定客服)
        # openid = msg_json.get("FromUserName") # 不再直接使用此openid传递给fetch_and_respond

        if (
            msg_json.get("MsgType") == "event"
            and msg_json.get("Event") == "kf_msg_or_event"
        ):
            # 当有新消息事件时，使用配置的企业微信客服 OPEN_KFID 来同步和响应消息
            fetch_and_respond(OPEN_KFID)
        
        return "success"
    except Exception as e:
        print("❌ 回调处理失败:", e)
        traceback.print_exc() # 打印完整的错误堆栈信息
        return "error", 500
    # 此处是 wechat_kf 函数的结尾，原先的重复错误代码已被移除

def get_wecom_access_token():
    corpid = os.getenv("CORPID")
    corpsecret = os.getenv("SECRET")
    url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={corpid}&corpsecret={corpsecret}"
    res = requests.get(url).json()
    if res.get("errcode") != 0:
        raise Exception(f"❌ 获取 access_token 失败: {res}")
    return res["access_token"]

def fetch_and_respond(open_kfid_to_sync): # 参数名修改以更清晰地反映其用途
    try:
        access_token = get_wecom_access_token()
        print("✅ 获取 access_token 成功")

        res = requests.post(
            f"https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token={access_token}",
            json={ "open_kfid": open_kfid_to_sync, "cursor": "" } # 使用传入的客服ID
        ).json()

        if res.get("errcode") != 0:
            raise Exception(f"❌ 拉取消息失败: {res}")

        msg_list = res.get("msg_list", [])
        print("📥 收到消息列表:", msg_list)

        for msg in msg_list:
            if msg.get("msgtype") == "text":
                content = msg["text"]["content"]
                external_userid = msg["external_userid"] # 这是发送消息的用户的ID

                # 检查缓存
                cached_reply = get_cached_response(external_userid, content)
                if cached_reply:
                    print("🤖 使用缓存回复:", cached_reply)
                    reply_text = cached_reply
                else:
                    # 使用 openai SDK 调用 GPT
                    # 确保 OPENAI_API_KEY 环境变量已设置，并且 openai 库版本适配
                    gpt_response = openai.chat.completions.create(
                        model="gpt-3.5-turbo",
                        messages=[
                            {"role": "system", "content": """你是一个中文果蔬商店的智能客服，以下是你售卖的商品清单（价格为单位售价）：
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
5. 回复请简洁明了，直接说结果。"""}, # 注意：原先ask_gpt中的 "避免多余寒暄" 在这里没有，如果需要可以加上。
                            {"role": "user", "content": content}
                        ],
                        temperature=0.3,
                    )
                    reply_text = gpt_response.choices[0].message.content.strip()
                    print("🤖 GPT 回复:", reply_text)
                    # 缓存回复
                    cache_response(external_userid, content, reply_text)

                send_res = requests.post(
                    f"https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg?access_token={access_token}",
                    json={
                        "touser": external_userid, # 发送给具体用户
                        "open_kfid": open_kfid_to_sync, # 使用哪个客服身份发送
                        "msgtype": "text",
                        "text": {"content": reply_text},
                    },
                ).json()
                print("📤 微信发送结果:", send_res)

    except Exception as e:
        print(f"❌ 处理消息并回复失败 (客服ID: {open_kfid_to_sync}):", e)
        traceback.print_exc() # 在这里也加上traceback，便于调试fetch_and_respond内部的错误

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
