import os
# import json # json 导入了但未在您提供的这个版本中使用，可以考虑移除
import time
import hashlib
import traceback # 确保导入 traceback
from flask import Flask, request, abort # 引入 abort
from dotenv import load_dotenv
from wechatpy.enterprise.crypto import WeChatCrypto
# from wechatpy.client import WeChatClient # client 实例创建了但未在后续代码中使用
# from wechatpy.client.api import WeChatMessage # WeChatMessage 未使用
import requests
import xmltodict
import openai

load_dotenv()

app = Flask(__name__) # 保留一个 Flask app 初始化

TOKEN = os.getenv("TOKEN") # 用于回调验证和消息加解密的 Token
ENCODING_AES_KEY = os.getenv("ENCODING_AES_KEY")
CORPID = os.getenv("CORPID")
SECRET = os.getenv("SECRET") # 用于获取 access_token
OPEN_KFID = os.getenv("OPEN_KFID") # 您配置的默认/主要的客服ID，可能被事件中的ID覆盖
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# 确保 OpenAI API Key 已设置
# openai.api_key = OPENAI_API_KEY # 旧版用法，如果 openai 库版本 >= 1.0.0 通常会自动从环境变量读取

crypto = WeChatCrypto(TOKEN, ENCODING_AES_KEY, CORPID)
# client = WeChatClient(CORPID, SECRET) # 此 client 实例未在代码中使用，请确认是否需要

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
        print(f"OpenAI 完整响应: {response.text if 'response' in locals() else 'N/A'}")
        return "抱歉，理解您的意思时遇到点问题，可以换个方式问吗？"

@app.route("/wechat_kf_callback", methods=["GET", "POST"])
def wechat_kf():
    if request.method == "GET":
        # 企业微信 GET 验证回调地址
        msg_signature = request.args.get("msg_signature")
        timestamp = request.args.get("timestamp")
        nonce = request.args.get("nonce")
        echostr = request.args.get("echostr")

        if not all([msg_signature, timestamp, nonce, echostr]):
            print("❌ GET 请求缺少参数 (wechat_kf)")
            return "Missing parameters for GET verification", 400
        try:
            # 使用wechatpy的crypto模块进行验证
            decrypted_echostr = crypto.verify_url(msg_signature, timestamp, nonce, echostr)
            print("✅ URL 验证成功 (wechat_kf)")
            return decrypted_echostr # 必须返回解密后的 echostr 明文
        except Exception as e:
            print(f"❌ URL 验证失败 (wechat_kf): {e}")
            traceback.print_exc()
            return "Verification failed", 403

    elif request.method == "POST":
        try:
            msg_signature = request.args.get("msg_signature")
            timestamp = request.args.get("timestamp")
            nonce = request.args.get("nonce")
            encrypted_xml = request.data

            if not all([msg_signature, timestamp, nonce, encrypted_xml]):
                print("❌ POST 请求缺少参数或数据 (wechat_kf)")
                return "Missing POST parameters or data", 400

            msg = crypto.decrypt_message(encrypted_xml, msg_signature, timestamp, nonce)
            msg_dict = xmltodict.parse(msg)
            msg_json = msg_dict["xml"] # 通常 msg_dict["xml"] 是消息主体

            print(f"ℹ️ 收到解密的 POST 数据 (wechat_kf): {msg_json}")

            if (
                msg_json.get("MsgType") == "event"
                and msg_json.get("Event") == "kf_msg_or_event"
            ):
                print("ℹ️ 收到 kf_msg_or_event 事件, 开始处理...")
                # 从事件中获取 OpenKfId 和用于拉取消息的 Token
                # !!! 注意：您需要根据文档 https://kf.weixin.qq.com/api/doc/path/94745 确认XML中这两个字段的确切名称
                event_open_kfid = msg_json.get("OpenKfId") # 假设字段名为 OpenKfId
                event_kf_token = msg_json.get("Token")    # 假设字段名为 Token (此Token用于sync_msg)

                if not event_kf_token: # event_open_kfid 可能与全局 OPEN_KFID 一致或需要从事件中获取
                    print("❌ kf_msg_or_event 事件中缺少 Token 字段 (wechat_kf)")
                    # 根据业务逻辑决定是否返回错误，或者使用全局OPEN_KFID（如果event_open_kfid也为空）
                    # 这里暂时使用全局的 OPEN_KFID 如果事件中没有提供，但 event_kf_token 是必需的
                    target_kfid = event_open_kfid if event_open_kfid else OPEN_KFID
                    if not event_kf_token: # 再次检查，因为 event_kf_token 很关键
                        print("❌ 无法处理 kf_msg_or_event，因为事件中未提供 sync_msg 所需的 Token")
                        return "success" # 仍然返回 success，避免微信重试，但记录错误
                else:
                    target_kfid = event_open_kfid if event_open_kfid else OPEN_KFID # 如果事件没给OpenKfId，用全局的
                    fetch_and_respond(target_kfid, event_kf_token)
            
            return "success" # 异步处理，先回复微信服务器，避免重试
        except Exception as e:
            print(f"❌ POST 回调处理失败 (wechat_kf): {e}")
            traceback.print_exc()
            return "error", 500
    else:
        print(f"❌ 不支持的请求方法: {request.method} (wechat_kf)")
        abort(405) # Method Not Allowed


def get_wecom_access_token():
    try:
        corpid = os.getenv("CORPID")
        corpsecret = os.getenv("SECRET")
        if not all([corpid, corpsecret]):
            raise ValueError("CORPID 或 SECRET 环境变量未设置")

        url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={corpid}&corpsecret={corpsecret}"
        res = requests.get(url).json()
        if res.get("errcode") != 0 or "access_token" not in res:
            raise Exception(f"获取 access_token 失败: {res}")
        access_token = res["access_token"]
        print("✅ 获取 access_token 成功")
        return access_token
    except requests.exceptions.RequestException as e:
        print(f"❌ 请求 access_token 网络错误 (get_wecom_access_token): {e}")
        raise
    except Exception as e:
        print(f"❌ 获取 access_token 未知错误 (get_wecom_access_token): {e}")
        traceback.print_exc() # 打印详细错误
        raise


def fetch_and_respond(target_open_kfid, kf_event_sync_token):
    """
    拉取并回复客服消息。
    target_open_kfid: 需要拉取消息的客服OpenKfId (可能来自事件，或全局配置)
    kf_event_sync_token: 从 kf_msg_or_event 事件中获取的，用于 sync_msg 接口的 Token
    """
    try:
        access_token = get_wecom_access_token()
        print(f"✅ 开始为客服ID {target_open_kfid} 拉取消息，使用 event_token: {'******' if kf_event_sync_token else 'N/A'}")

        # !!! 注意：请根据文档 https://kf.weixin.qq.com/api/doc/path/94744 (读取消息)
        # 确认 sync_msg 接口的 JSON body 中是否需要以及如何传递 kf_event_sync_token。
        # 假设它是在 json body 中以 "token" 字段传递。
        sync_payload = {
            "open_kfid": target_open_kfid,
            "cursor": "",
            "limit": 100, # 可按需调整
            "token": kf_event_sync_token # 使用从事件中获取的KF_EVENT_TOKEN
        }
        
        # 检查kf_event_sync_token是否存在，如果接口强制要求此token
        if not kf_event_sync_token:
            print(f"❌ 缺少 kf_event_sync_token，无法调用 sync_msg (fetch_and_respond for kfid: {target_open_kfid})")
            # 根据实际情况，这里可能需要更复杂的错误处理或直接返回
            return

        print(f"ℹ️ 调用 sync_msg, payload: open_kfid='{target_open_kfid}', token='{kf_event_sync_token[:5]}...' (fetch_and_respond)")
        res = requests.post(
            f"https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token={access_token}",
            json=sync_payload
        ).json()

        if res.get("errcode") != 0:
            # 如果是 token 无效的错误，需要特别注意 kf_event_sync_token 的来源和正确性
            print(f"❌ 拉取消息失败 (fetch_and_respond for kfid: {target_open_kfid}): {res}")
            # 可以根据 res.get("errcode") 做更细致的错误处理
            # 例如：40001 access_token 无效, 40013 corpid 无效, 95000 open_kfid 无效, 95012 (kf_event_sync_token 无效或不匹配)
            # 95012 这个错误码是我编的，您需要查阅文档确认 sync_msg 关于 token 校验失败的错误码
            return # 拉取失败则不继续处理

        msg_list = res.get("msg_list", [])
        if not msg_list:
            print(f"ℹ️ 本次同步没有新消息 (fetch_and_respond for kfid: {target_open_kfid})")
            return

        print(f"📥 收到 {len(msg_list)} 条消息 (为客服ID {target_open_kfid}):", msg_list)

        for msg_item in msg_list:
            if msg_item.get("msgtype") == "text":
                content = msg_item["text"]["content"]
                external_userid = msg_item["external_userid"]
                # msgid = msg_item.get("msgid")

                print(f"💬 待处理消息: 来自 {external_userid}, 内容 '{content}' (fetch_and_respond)")

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
5. 回复请简洁明了，直接说结果。"""},
                        {"role": "user", "content": content}
                    ],
                    temperature=0.3,
                )
                reply_text = gpt_response.choices[0].message.content.strip()
                print("🤖 GPT 回复:", reply_text)

                send_payload = {
                    "touser": external_userid,
                    "open_kfid": target_open_kfid,
                    "msgtype": "text",
                    "text": {"content": reply_text},
                }
                send_res = requests.post(
                    f"https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg?access_token={access_token}",
                    json=send_payload
                ).json()
                
                if send_res.get("errcode") == 0:
                    print(f"📤 成功回复 {external_userid}: {reply_text} (fetch_and_respond)")
                else:
                    print(f"❌ 发送回复给 {external_userid} 失败: {send_res} (fetch_and_respond)")
            else:
                print(f"⏭️ 跳过非文本消息: {msg_item.get('msgtype')} (fetch_and_respond)")

    except requests.exceptions.RequestException as e:
        print(f"❌ 网络请求错误 (fetch_and_respond for kfid: {target_open_kfid}): {e}")
        traceback.print_exc()
    except Exception as e:
        print(f"❌ 处理并回复消息失败 (fetch_and_respond for kfid: {target_open_kfid}): {e}")
        traceback.print_exc()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
