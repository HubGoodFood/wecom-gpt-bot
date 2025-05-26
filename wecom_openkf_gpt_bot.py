import os
import hashlib
import time
import xmltodict
import requests
import base64 # 新增，用于GET请求处理
import struct  # 新增，用于GET请求处理
import traceback
from flask import Flask, request, abort
from dotenv import load_dotenv
from wechatpy.enterprise.crypto import WeChatCrypto
from wechatpy.exceptions import InvalidSignatureException, InvalidCorpIdException # 新增，用于GET请求处理
from wechatpy.utils import to_text # 新增，用于GET请求处理
import openai

# 加载 .env 环境变量
load_dotenv()

# 1. 初始化 Flask app FIRST
app = Flask(__name__)

# 2. 定义配置变量和 crypto 对象等
TOKEN = os.getenv("TOKEN") # 用于回调验证和消息加解密的 Token
ENCODING_AES_KEY = os.getenv("ENCODING_AES_KEY")
CORPID = os.getenv("CORPID")
SECRET = os.getenv("SECRET") # 用于获取 access_token
OPEN_KFID = os.getenv("OPEN_KFID") # 您配置的默认/主要的客服ID
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# 确保关键配置存在
if not all([TOKEN, ENCODING_AES_KEY, CORPID, SECRET, OPEN_KFID, OPENAI_API_KEY]):
    # 在实际部署中，这里可能应该直接让应用启动失败或记录严重错误
    print("❌ 错误：一个或多个必要的环境变量未设置！请检查 .env 文件或环境变量配置。")
    # exit(1) # 或者引发异常

crypto = WeChatCrypto(TOKEN, ENCODING_AES_KEY, CORPID)

# 消息缓存 (当前未被 fetch_and_respond 中的 GPT 调用所使用)
message_cache = {} # 和您文件中的 cache 变量名保持一致

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
    if entry and time.time() - entry["timestamp"] < 300: # 缓存有效期300秒
        print(f"🤖 使用缓存回复 (for user {user_id}): {entry['reply']}")
        return entry["reply"]
    return None

def cache_response(user_id, content, reply):
    key = f"{user_id}:{hashlib.md5(content.encode()).hexdigest()}"
    message_cache[key] = {"reply": reply, "timestamp": time.time()}
    print(f"📝 缓存新回复 (for user {user_id})")

# ask_gpt 函数 (当前未被 fetch_and_respond 中的 GPT 调用所使用，因为 fetch_and_respond 直接调用 openai.chat.completions.create)
# 如果需要集成缓存和此处的 ask_gpt 结构，fetch_and_respond 中的 OpenAI 调用部分需要修改
def ask_gpt(user_id, question): # 添加了 user_id 参数以匹配缓存逻辑
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
        response.raise_for_status() # 检查HTTP请求错误
        answer = response.json()["choices"][0]["message"]["content"].strip()
        print(f"🤖 GPT 回复 (ask_gpt for user {user_id}): {answer}")
        cache_response(user_id, question, answer) # 缓存回复
        return answer
    except requests.exceptions.RequestException as e:
        print(f"❌ 请求 OpenAI API 失败 (ask_gpt for user {user_id}): {e}")
        return "抱歉，我现在无法连接到智能服务，请稍后再试。"
    except (KeyError, IndexError, TypeError) as e: # 添加 TypeError
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
        echostr = request.args.get("echostr") # 这是加密的 echostr

        if not all([msg_signature, timestamp, nonce, echostr]):
            print("❌ GET 请求缺少参数 (wechat_kf)")
            return "Missing parameters for GET verification", 400
        
        try:
            # 手动实现 VerifyURL 的核心逻辑，避免 decrypt_message 强制解析XML
            # 步骤 1: 验证签名 (使用 wechatpy 内部的 _generate_signature)
            # 注意: _generate_signature 是一个 "内部" 方法, 直接使用有潜在风险 (库升级可能改变其行为)
            # 更推荐的做法是参照官方文档实现SHA1签名算法，或确认 wechatpy.utils.generate_signature 的正确用法。
            # expected_signature = wechatpy.utils.generate_signature(TOKEN, timestamp, nonce, echostr) # 理论上应该这样
            expected_signature = crypto._generate_signature(timestamp, nonce, echostr)
            if msg_signature != expected_signature:
                raise InvalidSignatureException(f"URL签名验证失败. Expected: {expected_signature}, Got: {msg_signature}")

            # 步骤 2: Base64 解码 echostr 并使用 AES 解密
            encrypted_echostr_bytes = base64.b64decode(echostr)
            decrypted_bytes = crypto.cipher.decrypt(encrypted_echostr_bytes)
            
            # 步骤 3: 解包解密后的数据
            # 格式: 16字节随机数 + 4字节消息长度(网络字节序) + 消息内容(echostr明文) + CorpID/ReceiveID
            if len(decrypted_bytes) < 20: # 至少16字节随机数 + 4字节长度
                raise ValueError("解密后的消息过短 (VerifyURL)")

            content_offset = 16  # 跳过16字节的随机数
            
            msg_len_bytes = decrypted_bytes[content_offset : content_offset + 4]
            msg_len = struct.unpack('>I', msg_len_bytes)[0] # 获取消息长度 (大端，网络字节序)
            content_offset += 4
            
            if len(decrypted_bytes) < content_offset + msg_len:
                raise ValueError("解密后的消息内容长度错误 (VerifyURL)")
            
            echostr_plain = to_text(decrypted_bytes[content_offset : content_offset + msg_len]) # 获取echostr明文
            content_offset += msg_len
            
            from_receive_id = to_text(decrypted_bytes[content_offset:]) # 获取CorpID
            
            # 步骤 4: 校验 CorpID
            if from_receive_id != crypto.corp_id: # crypto.corp_id 是初始化 WeChatCrypto 时传入的 CORPID
                raise InvalidCorpIdException(actual=from_receive_id, expected=crypto.corp_id)
            
            print("✅ URL 验证成功 (wechat_kf - 手动验证)")
            return echostr_plain # 返回解密后的 echostr 明文

        except InvalidSignatureException as e:
            print(f"❌ URL 验证失败: 签名无效 (wechat_kf): {e}")
            traceback.print_exc()
            return "Verification failed (Invalid Signature)", 403
        except InvalidCorpIdException as e:
            print(f"❌ URL 验证失败: CorpID 不匹配 (wechat_kf): {e}")
            traceback.print_exc()
            return "Verification failed (Invalid CorpID)", 403
        except Exception as e:
            print(f"❌ URL 验证失败: 其他解密或处理错误 (wechat_kf): {e}")
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

            # 对于 POST 请求，解密后的消息体确实是XML，所以这里用 decrypt_message 是合适的
            decrypted_xml_msg_str = crypto.decrypt_message(encrypted_xml, msg_signature, timestamp, nonce)
            
            msg_dict = xmltodict.parse(decrypted_xml_msg_str)
            # 通常，xmltodict.parse的结果中，根节点名是'xml'，其值是包含消息内容的字典
            msg_json = msg_dict.get("xml") 
            if msg_json is None: # 如果根节点不是'xml'，可能msg_dict本身就是所需内容（较少见）
                msg_json = msg_dict 
                print("⚠️ POST 解密后XML的根节点不是 'xml'，直接使用解析后的字典 (wechat_kf)")


            print(f"ℹ️ 收到解密的 POST 数据 (wechat_kf): {msg_json}")

            if (
                msg_json.get("MsgType") == "event"
                and msg_json.get("Event") == "kf_msg_or_event"
            ):
                print("ℹ️ 收到 kf_msg_or_event 事件, 开始处理...")
                # !!! 关键: 您需要根据文档 https://kf.weixin.qq.com/api/doc/path/94745 
                # !!! 确认实际 kf_msg_or_event 事件XML中这两个字段的确切名称和层级。
                event_open_kfid = msg_json.get("OpenKfId") 
                event_kf_token_from_event = msg_json.get("Token") # 这个Token是用于调用“读取消息”接口的

                if not event_kf_token_from_event: 
                    print("❌ kf_msg_or_event 事件中缺少必须的 Token 字段 (wechat_kf)")
                    # 企业微信要求必须响应 success，否则会重试。记录错误，但正常返回。
                    return "success" 
                
                # 如果事件中没有OpenKfId（不太可能），则使用全局配置的OPEN_KFID
                target_kfid_for_fetch = event_open_kfid if event_open_kfid else OPEN_KFID
                if not target_kfid_for_fetch: # 如果全局的也没配，或者事件的也没有
                     print(f"❌ 无法确定目标 OpenKfId (事件中: {event_open_kfid}, 全局: {OPEN_KFID}) (wechat_kf)")
                     return "success"

                fetch_and_respond(target_kfid_for_fetch, event_kf_token_from_event)
            
            return "success" # 异步处理，先回复微信服务器，避免重试
        except Exception as e:
            print(f"❌ POST 回调处理失败 (wechat_kf): {e}")
            traceback.print_exc()
            return "error", 500 # 通知微信处理失败
    else:
        print(f"❌ 不支持的请求方法: {request.method} (wechat_kf)")
        abort(405) # Method Not Allowed


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
    except requests.exceptions.RequestException as e:
        print(f"❌ 请求 access_token 网络错误 (get_wecom_access_token): {e}")
        traceback.print_exc()
        raise
    except Exception as e:
        print(f"❌ 获取 access_token 未知错误 (get_wecom_access_token): {e}")
        traceback.print_exc()
        raise


def fetch_and_respond(target_open_kfid, kf_event_sync_token):
    """
    拉取并回复客服消息。
    target_open_kfid: 需要拉取消息的客服OpenKfId (来自事件或全局配置)
    kf_event_sync_token: 从 kf_msg_or_event 事件中获取的，用于 sync_msg (或等效的“读取消息”) 接口的 Token
    """
    try:
        access_token = get_wecom_access_token() # 常规 access_token
        # 打印部分 token 以供调试，但避免完整打印敏感信息
        print(f"✅ 开始为客服ID {target_open_kfid} 拉取消息，使用 event_sync_token: {kf_event_sync_token[:5] if kf_event_sync_token else 'N/A'}... (fetch_and_respond)")

        # !!! 关键: 您需要根据文档 https://kf.weixin.qq.com/api/doc/path/94744 (读取消息)
        # !!! 确认 sync_msg 接口 (或文档中指定的“读取消息”接口) 的 JSON body 中
        # !!! 是否需要以及如何传递 kf_event_sync_token。
        # !!! 假设它是在 json body 中以 "token" 字段传递。如果字段名不同或传递方式不同，请修改此处。
        sync_payload = {
            "open_kfid": target_open_kfid,
            "cursor": "", # 首次拉取传空，后续传上次返回的 next_cursor
            "limit": 100, 
            "token": kf_event_sync_token # !!! 假设这里使用从事件中获取的 Token
        }
        
        print(f"ℹ️ 调用 sync_msg, URL params: access_token=***, Body: {sync_payload} (fetch_and_respond)")
        res = requests.post(
            f"https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token={access_token}",
            json=sync_payload
        ).json()

        if res.get("errcode") != 0:
            # !!! 特别注意: 如果错误码指示 kf_event_sync_token 无效或不匹配，
            # !!! 则需要仔细检查从事件中提取Token的字段名，以及 sync_msg 是否这样使用它。
            print(f"❌ 拉取消息失败 (fetch_and_respond for kfid: {target_open_kfid}): {res}")
            return 

        msg_list = res.get("msg_list", [])
        if not msg_list:
            print(f"ℹ️ 本次同步没有新消息 (fetch_and_respond for kfid: {target_open_kfid})")
            return

        next_cursor = res.get("next_cursor") # 获取 next_cursor 用于下次拉取
        print(f"📥 收到 {len(msg_list)} 条消息 (为客服ID {target_open_kfid}), next_cursor: {next_cursor} (fetch_and_respond)")

        for msg_item in msg_list:
            if msg_item.get("msgtype") == "text":
                content = msg_item["text"]["content"]
                external_userid = msg_item["external_userid"]
                # msgid = msg_item.get("msgid") # 可用于去重

                print(f"💬 待处理消息: 来自 {external_userid}, 内容 '{content}' (fetch_and_respond)")

                # 这里直接调用 openai.chat.completions.create
                # 如果要使用上面定义的 ask_gpt 和缓存，需要修改这里的调用方式
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
                    reply_text = "抱歉，我现在有点忙，请稍后再试。" # 默认回复

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

        # 如果有 next_cursor，且还想继续拉取，可以在这里递归调用或放入队列处理
        # if next_cursor and res.get("has_more"):
        #     print(f"ℹ️ 仍有更多消息，下次可用 cursor: {next_cursor}")
        #     # fetch_and_respond(target_open_kfid, kf_event_sync_token, next_cursor) # 需要修改函数签名以接受cursor

    except requests.exceptions.RequestException as e_req:
        print(f"❌ 网络请求错误 (fetch_and_respond for kfid: {target_open_kfid}): {e_req}")
        traceback.print_exc()
    except Exception as e_main:
        print(f"❌ 处理并回复消息失败 (fetch_and_respond for kfid: {target_open_kfid}): {e_main}")
        traceback.print_exc()

if __name__ == "__main__":
    print("🚀 服务启动中...")
    # 确保所有必要的环境变量都已加载且 crypto 对象已初始化
    if not crypto:
        print("CRITICAL: WeChatCrypto 对象未初始化！请检查环境变量和脚本顶部的配置。")
        exit(1)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
