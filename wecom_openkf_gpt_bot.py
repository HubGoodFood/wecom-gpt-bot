import os
import hashlib
import time
import xmltodict
import requests
import base64
import struct
import traceback
from flask import Flask, request, abort
from dotenv import load_dotenv
from wechatpy.enterprise.crypto import WeChatCrypto
from wechatpy.exceptions import InvalidSignatureException # 只导入 InvalidSignatureException
from wechatpy.utils import to_text
import openai

# 加载 .env 环境变量
load_dotenv()

# 1. 初始化 Flask app FIRST
app = Flask(__name__)

# 2. 定义配置变量和 crypto 对象等
TOKEN = os.getenv("TOKEN")
ENCODING_AES_KEY = os.getenv("ENCODING_AES_KEY")
CORPID = os.getenv("CORPID")
SECRET = os.getenv("SECRET")
OPEN_KFID = os.getenv("OPEN_KFID")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not all([TOKEN, ENCODING_AES_KEY, CORPID, SECRET, OPEN_KFID, OPENAI_API_KEY]):
    print("❌ 错误：一个或多个必要的环境变量未设置！请检查 .env 文件或环境变量配置。")
    # exit(1) # 在实际部署中，这里可能应该直接让应用启动失败

crypto = WeChatCrypto(TOKEN, ENCODING_AES_KEY, CORPID)

message_cache = {}

SYSTEM_PROMPT = """你是一个中文果蔬商店的智能客服，以下是你售卖的商品清单（价格为单位售价）：
土豆：$8/袋
菠菜：$4/把
玉米：$5/根
素食鸡：$12/包
鸡蛋：$6/盒

请根据用户提问用简洁中文作答，例如他们问‘我要两袋土豆’，你应该回答‘好的，两袋土豆一共是$16。请问您还需要购买其他商品吗？’。你不需要自我介绍或道谢，直接回复关键信息。
"""

def get_cached_response(user_id, content):
    key = f"{user_id}:{hashlib.md5(content.encode()).hexdigest()}"
    entry = message_cache.get(key)
    if entry and time.time() - entry["timestamp"] < 300:
        print(f"🤖 使用缓存回复 (for user {user_id}): {entry['reply']}")
        return entry["reply"]
    return None

def cache_response(user_id, content, reply):
    key = f"{user_id}:{hashlib.md5(content.encode()).hexdigest()}"
    message_cache[key] = {"reply": reply, "timestamp": time.time()}
    print(f"📝 缓存新回复 (for user {user_id})")

def ask_gpt(user_id, question):
    cached_reply = get_cached_response(user_id, question)
    if cached_reply:
        return cached_reply

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "gpt-3.5-turbo",
        "temperature": 0.3,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": question}
        ]
    }
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        answer = response.json()["choices"][0]["message"]["content"].strip()
        print(f"🤖 GPT 回复 (ask_gpt for user {user_id}): {answer}")
        cache_response(user_id, question, answer)
        return answer
    except requests.exceptions.RequestException as e:
        print(f"❌ 请求 OpenAI API 失败 (ask_gpt for user {user_id}): {e}")
        return "抱歉，我现在无法连接到智能服务，请稍后再试。"
    except (KeyError, IndexError, TypeError) as e:
        print(f"❌ 解析 OpenAI API 响应失败 (ask_gpt for user {user_id}): {e}")
        full_response_text = "N/A"
        if 'response' in locals() and hasattr(response, 'text'):
            full_response_text = response.text
        print(f"OpenAI 完整响应 (ask_gpt): {full_response_text}")
        return "抱歉，理解您的意思时遇到点问题，可以换个方式问吗？"

@app.route("/wechat_kf_callback", methods=["GET", "POST"])
def wechat_kf():
    if request.method == "GET":
        msg_signature = request.args.get("msg_signature")
        timestamp = request.args.get("timestamp")
        nonce = request.args.get("nonce")
        echostr = request.args.get("echostr", "")
        # 使用 make_response 返回纯文本，确保 header 正确
        response = make_response(echostr)
        response.headers["Content-Type"] = "text/plain"
        return response

        if not all([msg_signature, timestamp, nonce, echostr]):
            print("❌ GET 请求缺少参数 (wechat_kf)")
            return "Missing parameters for GET verification", 400
        
        try:
            expected_signature = crypto._generate_signature(timestamp, nonce, echostr)
            if msg_signature != expected_signature:
                raise InvalidSignatureException(f"URL签名验证失败. Expected: {expected_signature}, Got: {msg_signature}")

            encrypted_echostr_bytes = base64.b64decode(echostr)
            decrypted_bytes = crypto.cipher.decrypt(encrypted_echostr_bytes)
            
            if len(decrypted_bytes) < 20:
                raise ValueError("解密后的消息过短 (VerifyURL)")

            content_offset = 16
            msg_len_bytes = decrypted_bytes[content_offset : content_offset + 4]
            msg_len = struct.unpack('>I', msg_len_bytes)[0]
            content_offset += 4
            
            if len(decrypted_bytes) < content_offset + msg_len:
                raise ValueError("解密后的消息内容长度错误 (VerifyURL)")
            
            echostr_plain = to_text(decrypted_bytes[content_offset : content_offset + msg_len])
            content_offset += msg_len
            from_receive_id = to_text(decrypted_bytes[content_offset:])
            
            if from_receive_id != crypto.corp_id:
                # 主动抛出 ValueError 来指示 CorpID 不匹配
                raise ValueError(f"CorpID 不匹配. Expected: {crypto.corp_id}, Got: {from_receive_id}")
            
            print("✅ URL 验证成功 (wechat_kf - 手动验证)")
            return echostr_plain

        except InvalidSignatureException as e:
            print(f"❌ URL 验证失败: 签名无效 (wechat_kf): {e}")
            traceback.print_exc()
            return "Verification failed (Invalid Signature)", 403
        except ValueError as e: # 捕获上面主动抛出的 ValueError 或其他解包错误
            print(f"❌ URL 验证失败: 数据处理错误或CorpID不匹配 (wechat_kf): {e}")
            traceback.print_exc()
            return "Verification failed (Data Error or Invalid CorpID)", 403
        except Exception as e:
            print(f"❌ URL 验证失败: 其他错误 (wechat_kf): {e}")
            traceback.print_exc()
            return "Verification failed (Processing Error)", 403

    elif request.method == "POST":
        try:
            msg_signature = request.args.get("msg_signature")
            timestamp = request.args.get("timestamp")
            nonce = request.args.get("nonce")
            encrypted_xml = request.data

            if not all([msg_signature, timestamp, nonce, encrypted_xml]):
                print("❌ POST 请求缺少参数或数据 (wechat_kf)")
                return "Missing POST parameters or data", 400

            decrypted_xml_msg_str = crypto.decrypt_message(encrypted_xml, msg_signature, timestamp, nonce)
            msg_dict = xmltodict.parse(decrypted_xml_msg_str)
            msg_json = msg_dict.get("xml") 
            if msg_json is None:
                msg_json = msg_dict 
                print("⚠️ POST 解密后XML的根节点不是 'xml'，直接使用解析后的字典 (wechat_kf)")

            print(f"ℹ️ 收到解密的 POST 数据 (wechat_kf): {msg_json}")

            if (
                msg_json.get("MsgType") == "event"
                and msg_json.get("Event") == "kf_msg_or_event"
            ):
                print("ℹ️ 收到 kf_msg_or_event 事件, 开始处理...")
                event_open_kfid = msg_json.get("OpenKfId") 
                event_kf_token_from_event = msg_json.get("Token")

                if not event_kf_token_from_event: 
                    print("❌ kf_msg_or_event 事件中缺少必须的 Token 字段 (wechat_kf)")
                    return "success" 
                
                target_kfid_for_fetch = event_open_kfid if event_open_kfid else OPEN_KFID
                if not target_kfid_for_fetch:
                     print(f"❌ 无法确定目标 OpenKfId (事件中: {event_open_kfid}, 全局: {OPEN_KFID}) (wechat_kf)")
                     return "success"

                fetch_and_respond(target_kfid_for_fetch, event_kf_token_from_event)
            
            return "success"
        except Exception as e:
            print(f"❌ POST 回调处理失败 (wechat_kf): {e}")
            traceback.print_exc()
            return "error", 500
    else:
        print(f"❌ 不支持的请求方法: {request.method} (wechat_kf)")
        abort(405)

def get_wecom_access_token():
    try:
        corpid = os.getenv("CORPID")
        corpsecret = os.getenv("SECRET")
        if not all([corpid, corpsecret]):
            raise ValueError("CORPID 或 SECRET 环境变量未设置 (get_wecom_access_token)")

        url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={corpid}&corpsecret={corpsecret}"
        res = requests.get(url).json()

        if res.get("errcode") != 0 or "access_token" not in res:
            raise Exception(f"获取 access_token 失败: {res} (get_wecom_access_token)")
        access_token = res["access_token"]
        print("✅ 获取 access_token 成功 (get_wecom_access_token)")
        return access_token
    except requests.exceptions.RequestException as e_req: # 更具体的网络异常捕获
        print(f"❌ 请求 access_token 网络错误 (get_wecom_access_token): {e_req}")
        traceback.print_exc()
        raise
    except Exception as e:
        print(f"❌ 获取 access_token 未知错误 (get_wecom_access_token): {e}")
        traceback.print_exc()
        raise

def fetch_and_respond(target_open_kfid, kf_event_sync_token):
    try:
        access_token = get_wecom_access_token()
        print(f"✅ 开始为客服ID {target_open_kfid} 拉取消息，使用 event_sync_token: {kf_event_sync_token[:5] if kf_event_sync_token else 'N/A'}... (fetch_and_respond)")

        sync_payload = {
            "open_kfid": target_open_kfid,
            "cursor": "", 
            "limit": 100, 
            "token": kf_event_sync_token 
        }
        
        if not kf_event_sync_token: # 再次检查，确保 token 存在
            print(f"❌ 缺少 kf_event_sync_token，无法调用 sync_msg (fetch_and_respond for kfid: {target_open_kfid})")
            return

        print(f"ℹ️ 调用 sync_msg, URL params: access_token=***, Body: {sync_payload} (fetch_and_respond)")
        res = requests.post(
            f"https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token={access_token}",
            json=sync_payload
        ).json()

        if res.get("errcode") != 0:
            print(f"❌ 拉取消息失败 (fetch_and_respond for kfid: {target_open_kfid}): {res}")
            return 

        msg_list = res.get("msg_list", [])
        if not msg_list:
            print(f"ℹ️ 本次同步没有新消息 (fetch_and_respond for kfid: {target_open_kfid})")
            return

        next_cursor = res.get("next_cursor")
        print(f"📥 收到 {len(msg_list)} 条消息 (为客服ID {target_open_kfid}), next_cursor: {next_cursor} (fetch_and_respond)")

        for msg_item in msg_list:
            if msg_item.get("msgtype") == "text":
                content = msg_item["text"]["content"]
                external_userid = msg_item["external_userid"]

                print(f"💬 待处理消息: 来自 {external_userid}, 内容 '{content}' (fetch_and_respond)")
                try:
                    gpt_response = openai.chat.completions.create(
                        model="gpt-3.5-turbo",
                        messages=[
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": content}
                        ],
                        temperature=0.3,
                    )
                    reply_text = gpt_response.choices[0].message.content.strip()
                    print(f"🤖 GPT 回复 (to {external_userid}): {reply_text}")
                except Exception as e_gpt:
                    print(f"❌ 调用 OpenAI 失败 (fetch_and_respond for user {external_userid}): {e_gpt}")
                    traceback.print_exc()
                    reply_text = "抱歉，我现在有点忙，请稍后再试。"

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
                    print(f"📤 成功回复 {external_userid} (fetch_and_respond)")
                else:
                    print(f"❌ 发送回复给 {external_userid} 失败: {send_res} (fetch_and_respond)")
            else:
                print(f"⏭️ 跳过非文本消息: type='{msg_item.get('msgtype')}', from_user='{msg_item.get('external_userid', 'N/A')}' (fetch_and_respond)")

    except requests.exceptions.RequestException as e_req:
        print(f"❌ 网络请求错误 (fetch_and_respond for kfid: {target_open_kfid}): {e_req}")
        traceback.print_exc()
    except Exception as e_main:
        print(f"❌ 处理并回复消息失败 (fetch_and_respond for kfid: {target_open_kfid}): {e_main}")
        traceback.print_exc()

if __name__ == "__main__":
    print("🚀 服务启动中...")
    if 'crypto' not in globals() or not isinstance(crypto, WeChatCrypto):
        print("CRITICAL: WeChatCrypto 对象未正确初始化！请检查环境变量和脚本顶部的配置。")
        exit(1) # 确保 crypto 对象已创建
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
