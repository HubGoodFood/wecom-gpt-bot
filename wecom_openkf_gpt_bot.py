import os
import hashlib
import time
import xmltodict
import requests
from flask import Flask, request, abort # 确保 Flask 在这里导入
from wechatpy.enterprise.crypto import WeChatCrypto
from dotenv import load_dotenv
import traceback
import openai # 确保 openai 也导入了

# 加载 .env 环境变量
load_dotenv()

# 1. 初始化 Flask app FIRST
app = Flask(__name__)

# 2. 然后再定义配置变量和 crypto 对象等
TOKEN = os.getenv("TOKEN")
ENCODING_AES_KEY = os.getenv("ENCODING_AES_KEY")
CORPID = os.getenv("CORPID")
SECRET = os.getenv("SECRET")
OPEN_KFID = os.getenv("OPEN_KFID")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

crypto = WeChatCrypto(TOKEN, ENCODING_AES_KEY, CORPID)

# ... 其他全局变量如 cache, SYSTEM_PROMPT 等 ...
message_cache = {} # 和您文件中的 cache 变量名保持一致

SYSTEM_PROMPT = """你是一个中文果蔬商店的智能客服，以下是你售卖的商品清单（价格为单位售价）：
土豆：$8/袋
菠菜：$4/把
玉米：$5/根
素食鸡：$12/包
鸡蛋：$6/盒

请根据用户提问用简洁中文作答，例如他们问‘我要两袋土豆’，你应该回答‘好的，两袋土豆一共是$16。请问您还需要购买其他商品吗？’。你不需要自我介绍或道谢，直接回复关键信息。
"""

# ... 接下来是您的函数定义 (get_cached_response, cache_response, ask_gpt) ...

# 3. 再之后才是使用 @app.route 的路由定义
@app.route("/wechat_kf_callback", methods=["GET", "POST"])
def wechat_kf():
    # ... (GET 和 POST 的处理逻辑) ...
    # (这里使用我上一条回复中修正后的 wechat_kf 函数逻辑)
    if request.method == "GET":
        msg_signature = request.args.get("msg_signature")
        timestamp = request.args.get("timestamp")
        nonce = request.args.get("nonce")
        echostr = request.args.get("echostr")

        if not all([msg_signature, timestamp, nonce, echostr]):
            print("❌ GET 请求缺少参数 (wechat_kf)")
            return "Missing parameters for GET verification", 400
        try:
            decrypted_echostr = crypto.decrypt_message(echostr, msg_signature, timestamp, nonce)
            print("✅ URL 验证成功 (wechat_kf)")
            return decrypted_echostr
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
            msg_json = msg_dict["xml"]

            print(f"ℹ️ 收到解密的 POST 数据 (wechat_kf): {msg_json}")

            if (
                msg_json.get("MsgType") == "event"
                and msg_json.get("Event") == "kf_msg_or_event"
            ):
                print("ℹ️ 收到 kf_msg_or_event 事件, 开始处理...")
                event_open_kfid = msg_json.get("OpenKfId")
                event_kf_token = msg_json.get("Token")

                if not event_kf_token:
                    print("❌ kf_msg_or_event 事件中缺少 Token 字段 (wechat_kf)")
                    target_kfid = event_open_kfid if event_open_kfid else OPEN_KFID
                    if not event_kf_token:
                        print("❌ 无法处理 kf_msg_or_event，因为事件中未提供 sync_msg 所需的 Token")
                        return "success"
                else:
                    target_kfid = event_open_kfid if event_open_kfid else OPEN_KFID
                    fetch_and_respond(target_kfid, event_kf_token)
            
            return "success"
        except Exception as e:
            print(f"❌ POST 回调处理失败 (wechat_kf): {e}")
            traceback.print_exc()
            return "error", 500
    else:
        print(f"❌ 不支持的请求方法: {request.method} (wechat_kf)")
        abort(405)

# ... (get_wecom_access_token 和 fetch_and_respond 函数定义) ...
# (这些函数使用我上一条回复中修正后的逻辑)

# 4. 最后是 if __name__ == "__main__": app.run(...)
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
