import os
import time
import base64
import hashlib
import xml.etree.ElementTree as ET
import requests
from flask import Flask, request
from dotenv import load_dotenv
from Crypto.Cipher import AES
import xmltodict
import sys
import logging

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

app = Flask(__name__)

CORPID = os.getenv("CORPID")
AGENTID = os.getenv("AGENTID")
SECRET = os.getenv("SECRET")
TOKEN = os.getenv("TOKEN")
ENCODING_AES_KEY = os.getenv("ENCODING_AES_KEY")

class WXBizMsgCrypt:
    def __init__(self, token, encodingAESKey, corpId):
        self.key = base64.b64decode(encodingAESKey + "=")
        self.token = token
        self.corpId = corpId

    def _pad(self, s):
        bs = AES.block_size
        pad_num = bs - len(s) % bs
        return s + bytes([pad_num] * pad_num)

    def _unpad(self, s):
        return s[:-s[-1]]

    def decrypt(self, encrypt):
        cipher = AES.new(self.key, AES.MODE_CBC, self.key[:16])
        plain = cipher.decrypt(base64.b64decode(encrypt))
        plain = self._unpad(plain)
        xml_len = int.from_bytes(plain[16:20], byteorder='big')
        xml_content = plain[20:20+xml_len]
        from_corpid = plain[20+xml_len:].decode()
        assert from_corpid == self.corpId
        return xml_content.decode()

cryptor = WXBizMsgCrypt(TOKEN, ENCODING_AES_KEY, CORPID)

def get_access_token():
    url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={CORPID}&corpsecret={SECRET}"
    r = requests.get(url)
    data = r.json()
    if "access_token" in data:
        logging.info("✅ 获取 access_token 成功")
        return data["access_token"]
    else:
        logging.error("❌ 获取 access_token 失败: %s", data)
        return None

def send_text_message(user_id, content):
    access_token = get_access_token()
    if not access_token:
        return
    url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={access_token}"
    payload = {
        "touser": user_id,
        "msgtype": "text",
        "agentid": AGENTID,
        "text": {"content": content},
        "safe": 0
    }
    r = requests.post(url, json=payload)
    logging.info("📤 消息发送结果: %s", r.text)

@app.route("/", methods=["GET", "POST", "HEAD"])
def wechat_callback():
    logging.info("🚨 wechat_callback 被触发")
    logging.info("🔍 method: %s", request.method)

    msg_signature = request.args.get("msg_signature", "")
    timestamp = request.args.get("timestamp", "")
    nonce = request.args.get("nonce", "")

    try:
        if request.method == "GET":
            echostr = request.args.get("echostr")
            if echostr:
                try:
                    echo = cryptor.decrypt(echostr)
                    logging.info("✅ 解密 echostr 成功: %s", echo)
                    return echo
                except Exception as e:
                    logging.warning("⚠️ echostr 解密失败: %s", str(e))
                    return "invalid echostr", 400
            else:
                return "WeCom bot is running", 200

        if request.method == "POST":
            raw_xml = request.data.decode(errors='ignore')
            logging.info("📦 原始 XML: %s", raw_xml)

            xml_tree = ET.fromstring(raw_xml)
            encrypt = xml_tree.find("Encrypt").text
            logging.info("🔐 提取 Encrypt: %s", encrypt)

            decrypted_xml = cryptor.decrypt(encrypt)
            logging.info("📖 解密后 XML: %s", decrypted_xml)

            msg = xmltodict.parse(decrypted_xml)["xml"]
            content = msg.get("Content")
            from_user = msg.get("FromUserName")
            logging.info("🧾 用户发来内容: %s", content)

            reply = "你好，我是果蔬客服机器人，正在测试中~"
            send_text_message(from_user, reply)

            return "success", 200

        if request.method == "HEAD":
            return "", 200

    except Exception as e:
        logging.error("❌ 异常: %s", str(e))
        try:
            logging.error("📦 原始 XML: %s", request.data.decode(errors='ignore'))
        except:
            pass
        return "error", 500

if __name__ == "__main__":
    logging.info("✅ 启动主动发送版 Flask 成功")
    app.run(host="0.0.0.0", port=10000)