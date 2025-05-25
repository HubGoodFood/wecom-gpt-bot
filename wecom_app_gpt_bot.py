import os
import time
import base64
import hashlib
import xml.etree.ElementTree as ET
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

    def encrypt(self, reply_msg, nonce, timestamp):
        raw = os.urandom(16)
        msg_len = len(reply_msg)
        msg = raw + msg_len.to_bytes(4, 'big') + reply_msg.encode() + self.corpId.encode()
        msg = self._pad(msg)
        cipher = AES.new(self.key, AES.MODE_CBC, self.key[:16])
        encrypted = base64.b64encode(cipher.encrypt(msg)).decode()
        sign_list = [self.token, timestamp, nonce, encrypted]
        sign_list.sort()
        sha = hashlib.sha1()
        sha.update(''.join(sign_list).encode())
        signature = sha.hexdigest()
        return encrypted, signature

cryptor = WXBizMsgCrypt(TOKEN, ENCODING_AES_KEY, CORPID)

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
            to_user = msg.get("FromUserName")    # 用户
            from_user = msg.get("ToUserName")    # 机器人
            agent_id = msg.get("AgentID")

            logging.info("🧾 用户发来内容: %s", content)

            reply = "你好，我是果蔬客服机器人，正在测试中~"

            reply_xml = f"""<xml>
<ToUserName><![CDATA[{to_user}]]></ToUserName>
<FromUserName><![CDATA[{from_user}]]></FromUserName>
<CreateTime>{int(time.time())}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[{reply}]]></Content>
<AgentID><![CDATA[{agent_id}]]></AgentID>
</xml>"""
            encrypted, signature = cryptor.encrypt(reply_xml, nonce, timestamp)
            response = f"<xml><Encrypt><![CDATA[{encrypted}]]></Encrypt><MsgSignature><![CDATA[{signature}]]></MsgSignature><TimeStamp>{timestamp}</TimeStamp><Nonce><![CDATA[{nonce}]]></Nonce></xml>"
            return response, 200, {"Content-Type": "application/xml"}

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
    logging.info("✅ 启动完整客服版本 Flask 成功")
    app.run(host="0.0.0.0", port=10000)