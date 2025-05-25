import os
import json # json 导入了但未在您提供的这个版本中使用，可以考虑移除
import time
import hashlib
import traceback # 确保导入 traceback
from flask import Flask, request
from dotenv import load_dotenv
from wechatpy.enterprise.crypto import WeChatCrypto
from wechatpy.client import WeChatClient # client 实例创建了但未在后续代码中使用
# from wechatpy.client.api import WeChatMessage # WeChatMessage 未使用
from flask import request, Flask
import requests
import xmltodict # 添加缺失的导入
import openai # 添加缺失的导入

load_dotenv()

app = Flask(__name__)

TOKEN = os.getenv("TOKEN")
ENCODING_AES_KEY = os.getenv("ENCODING_AES_KEY")
CORPID = os.getenv("CORPID")
SECRET = os.getenv("SECRET")
OPEN_KFID = os.getenv("OPEN_KFID") # 您的企业微信客服ID
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# 确保 OpenAI API Key 已设置，如果 openai 库版本 >= 1.0.0
# openai.api_key = OPENAI_API_KEY # 旧版用法
# 或者 client_openai = openai.OpenAI(api_key=OPENAI_API_KEY) # 新版用法

app = Flask(__name__)
crypto = WeChatCrypto(TOKEN, ENCODING_AES_KEY, CORPID)
client = WeChatClient(CORPID, SECRET) # 此 client 实例未在代码中使用，请确认是否需要

# 消息缓存 (当前未被 fetch_and_respond 中的 GPT 调用所使用)
message_cache = {}

def get_cached_response(user_id, content):
    key = f"{user_id}:{hashlib.md5(content.encode()).hexdigest()}"
    entry = message_cache.get(key)
    if entry and time.time() - entry["timestamp"] < 300:
        return entry["reply"]
    return None

def cache_response(user_id, content, reply):
    key = f"{user_id}:{hashlib.md5(content.encode()).hexdigest()}"
    message_cache[key] = {"reply": reply, "timestamp": time.time()}

# ask_gpt 函数 (当前未被 fetch_and_respond 中的 GPT 调用所使用)
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
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]
    except requests.exceptions.RequestException as e:
        print(f"❌ 请求 OpenAI API 失败 (ask_gpt): {e}")
        return "抱歉，我现在无法连接到智能服务，请稍后再试。"
    except (KeyError, IndexError) as e:
        print(f"❌ 解析 OpenAI API 响应失败 (ask_gpt): {e}")
        return "抱歉，理解您的意思时遇到点问题，可以换个方式问吗？"


@app.route("/wechat_kf_callback", methods=["GET", "POST"])
def wechat_kf():
    if request.method == "GET":
        # 企业微信 GET 验证回调地址
        echostr = request.args.get("echostr", "")
        return echostr
    try:
        msg_signature = request.args.get("msg_signature")
        timestamp = request.args.get("timestamp")
        nonce = request.args.get("nonce")
        encrypted_xml = request.data

        if not all([msg_signature, timestamp, nonce, encrypted_xml]):
            print("❌ POST 请求缺少参数或数据")
            return "Missing POST parameters or data", 400

        msg = crypto.decrypt_message(encrypted_xml, msg_signature, timestamp, nonce)
        msg_dict = xmltodict.parse(msg) # 您日志中报错的行 (line 83)
        msg_json = msg_dict["xml"]

        # openid = msg_json.get("FromUserName") # 这是用户的 external_userid

        if (
            msg_json.get("MsgType") == "event"
            and msg_json.get("Event") == "kf_msg_or_event"
        ):
            print("ℹ️ 收到 kf_msg_or_event 事件, 开始处理...")
            # 调用 fetch_and_respond 时使用配置的 OPEN_KFID
            fetch_and_respond(OPEN_KFID)
        
        return "success"
    except Exception as e:
        print(f"❌ POST 回调处理失败 (wechat_kf): {e}")
        traceback.print_exc() # 打印完整的错误堆栈信息
        return "error", 500
    # END OF wechat_kf FUNCTION - 确保原先在此之后的重复错误代码块已被删除

def get_wecom_access_token():
    try:
        corpid = os.getenv("CORPID")
        corpsecret = os.getenv("SECRET")
        url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={corpid}&corpsecret={corpsecret}"
        res = requests.get(url).json()
        if res.get("errcode") != 0 or "access_token" not in res: # 更严格的检查
            raise Exception(f"获取 access_token 失败: {res}")
        return res["access_token"]
    except requests.exceptions.RequestException as e:
        print(f"❌ 请求 access_token 网络错误: {e}")
        raise # 将网络请求异常重新抛出，以便上层捕获
    except Exception as e: # 捕获其他可能的错误
        print(f"❌ 获取 access_token 未知错误: {e}")
        raise # 将未知异常重新抛出


def fetch_and_respond(open_kfid_to_sync): # 参数名修改以反映其用途
    try:
        access_token = get_wecom_access_token()
        print(f"✅ 获取 access_token 成功 (用于客服ID: {open_kfid_to_sync})")

        sync_payload = {
            "open_kfid": open_kfid_to_sync,
            "cursor": "",
            "limit": 100 # 可按需调整
            # 这个版本的 sync_msg 调用中没有包含 "token": TOKEN 参数，
            # 如果您的回调配置需要，可以加上："token": TOKEN
        }
        res = requests.post(
            f"https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token={access_token}",
            json=sync_payload
        ).json()

        if res.get("errcode") != 0:
            raise Exception(f"拉取消息失败: {res}")

        msg_list = res.get("msg_list", [])
        if not msg_list:
            print("ℹ️ 本次同步没有新消息。")
            return

        print(f"📥 收到 {len(msg_list)} 条消息 (为客服ID: {open_kfid_to_sync}):", msg_list)

        for msg_item in msg_list: # 变量名修改避免与外层 msg 冲突
            if msg_item.get("msgtype") == "text":
                content = msg_item["text"]["content"]
                external_userid = msg_item["external_userid"]
                # msgid = msg_item.get("msgid") # 消息ID，可用于去重或记录

                print(f"💬 待处理消息: 来自 {external_userid}, 内容 '{content}'")

                # 使用 openai SDK 调用 GPT
                # (当前未与上面定义的 ask_gpt 和缓存逻辑集成)
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
3. 遇到打招呼（如“你好”、“在吗”）仅回复一次问候语“你好，请问有什么可以帮助您的呢？”。
4. 如果用户提到未列出的商品，回复“目前没有此商品”，并推荐已有商品。
5. 回复请简洁明了，直接说结果。"""}, # 您可以从 ask_gpt 函数中同步 system prompt
                        {"role": "user", "content": content}
                    ],
                    temperature=0.3,
                )
                reply_text = gpt_response.choices[0].message.content.strip()
                print("🤖 GPT 回复:", reply_text)

                send_payload = {
                    "touser": external_userid,
                    "open_kfid": open_kfid_to_sync, # 使用哪个客服身份发送
                    "msgtype": "text",
                    "text": {"content": reply_text},
                }
                send_res = requests.post(
                    f"https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg?access_token={access_token}",
                    json=send_payload
                ).json()
                
                if send_res.get("errcode") == 0:
                    print(f"📤 成功回复 {external_userid}: {reply_text}")
                else:
                    print(f"❌ 发送回复给 {external_userid} 失败: {send_res}")
            else:
                print(f"⏭️ 跳过非文本消息: {msg_item.get('msgtype')}")

    except requests.exceptions.RequestException as e:
        print(f"❌ 网络请求错误 (fetch_and_respond): {e}")
        traceback.print_exc()
    except Exception as e:
        print(f"❌ 处理并回复消息失败 (fetch_and_respond, 客服ID: {open_kfid_to_sync}): {e}")
        traceback.print_exc() # 添加 traceback 打印

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
