import os
import logging
import xmltodict
from flask import Flask, request, make_response
from wechatpy.enterprise.crypto import WeChatCrypto
from wechatpy.client import WeChatClient
from wechatpy.client.api import WeChatMessage

# === 配置项 ===
WECHAT_TOKEN = os.getenv("WECHAT_TOKEN")
WECHAT_ENCODING_AES_KEY = os.getenv("WECHAT_ENCODING_AES_KEY")
WECHAT_CORP_ID = os.getenv("WECHAT_CORP_ID")
WECHAT_APP_SECRET = os.getenv("WECHAT_APP_SECRET")
OPEN_KFID = os.getenv("OPEN_KFID")

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

crypto = WeChatCrypto(WECHAT_TOKEN, WECHAT_ENCODING_AES_KEY, WECHAT_CORP_ID)
client = WeChatClient(WECHAT_CORP_ID, WECHAT_APP_SECRET)

# === 路由处理 ===

@app.route("/wechat_kf_callback", methods=["GET", "POST"])
def wechat_kf_callback():
    msg_signature = request.args.get("msg_signature")
    timestamp = request.args.get("timestamp")
    nonce = request.args.get("nonce")

    if request.method == "GET":
        echostr = request.args.get("echostr", "")
        try:
            decrypted = crypto.check_signature(msg_signature, timestamp, nonce, echostr)
            return make_response(echostr)
        except Exception as e:
            logger.error(f"❌ URL验证失败: {e}")
            return "error", 400

    if request.method == "POST":
        try:
            encrypted_xml = request.data
            msg = crypto.decrypt_message(encrypted_xml, msg_signature, timestamp, nonce)
            msg_dict = xmltodict.parse(msg)
            msg_json = msg_dict["xml"]
            logger.info(f"📥 解密后消息: {msg_json}")

            if msg_json.get("MsgType") == "event" and msg_json.get("Event") == "kf_msg_or_event":
                logger.info("✅ 收到消息事件，准备处理 GPT 回复")
                open_kfid = msg_json.get("ToUserName")
                external_userid = msg_json.get("FromUserName")
                fetch_and_respond(open_kfid, external_userid)
        except Exception as e:
            logger.error(f"❌ 回调处理失败: {e}")
            return "error", 500

    return "success"


# === 消息同步与回复 ===

def fetch_and_respond(open_kfid, external_userid):
    try:
        access_token = client.access_token
        logger.info("✅ 获取 access_token 成功")
        sync_url = "https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg"
        sync_res = client.get(sync_url, params={"cursor": "", "token": access_token})
        logger.info(f"📥 收到消息列表: {sync_res}")

        last_msg = None
        for msg in sync_res.get("msg_list", []):
            if msg.get("msgtype") == "text":
                last_msg = msg["text"]["content"]

        if last_msg:
            logger.info(f"🤖 GPT 回复: {last_msg}")
            reply = {"msgtype": "text", "text": {"content": f"你说的是: {last_msg}"}}
            send_url = "https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg"
            send_data = {
                "touser": external_userid,
                "open_kfid": open_kfid,
                "msgid": f"msg_{external_userid}",
                **reply,
            }
            send_res = client.post(send_url, data=send_data)
            logger.info(f"📤 微信发送结果: {send_res}")
    except Exception as e:
        raise Exception(f"拉取消息失败: {e}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))