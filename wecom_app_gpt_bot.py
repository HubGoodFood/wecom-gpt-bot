import os
import time
import base64
import hashlib
import xml.etree.ElementTree as ET
from flask import Flask, request
from dotenv import load_dotenv
import requests
from Crypto.Cipher import AES
import xmltodict

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
app = Flask(__name__)

CORPID = os.getenv("CORPID")
TOKEN = os.getenv("TOKEN")
ENCODING_AES_KEY = os.getenv("ENCODING_AES_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

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

def ask_gpt(question):
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "gpt-3.5-turbo",
        "messages": [
            {"role": "system", "content": "你是一个中文果蔬客服，回答顾客关于商品价格、规格、配送等问题。"},
            {"role": "user", "content": question}
        ]
    }
    res = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
    if res.status_code == 200:
        return res.json()["choices"][0]["message"]["content"]
    return "AI 回复失败。"

@app.route("/", methods=["GET", "POST", "HEAD"])
def wechat_callback():
    print("[DEBUG] 收到请求:", request.method, request.args)
    msg_signature = request.args.get("msg_signature", "")
    timestamp = request.args.get("timestamp", "")
    nonce = request.args.get("nonce", "")
    try:
        if request.method == "GET":
            echostr = request.args.get("echostr", "")
            echo = cryptor.decrypt(echostr)
            print("[DEBUG] 解密成功:", echo)
            return echo
        if request.method == "POST":
            xml = request.data
            xml_tree = ET.fromstring(xml)
            encrypt = xml_tree.find("Encrypt").text
            decrypted_xml = cryptor.decrypt(encrypt)
            msg = xmltodict.parse(decrypted_xml)["xml"]
            content = msg.get("Content")
            from_user = msg.get("FromUserName")
            to_user = msg.get("ToUserName")
#            reply = ask_gpt(content)
            print("[DEBUG] 收到微信消息:", content)

            reply = "你好，我是果蔬客服机器人（测试中）"
            reply_xml = f"""<xml>
  <ToUserName><![CDATA[{from_user}]]></ToUserName>
  <FromUserName><![CDATA[{to_user}]]></FromUserName>
  <CreateTime>{int(time.time())}</CreateTime>
  <MsgType><![CDATA[text]]></MsgType>
  <Content><![CDATA[{reply}]]></Content>
</xml>"""
            encrypted, signature = cryptor.encrypt(reply_xml, nonce, timestamp)
            response = f"""<xml>
  <Encrypt><![CDATA[{encrypted}]]></Encrypt>
  <MsgSignature><![CDATA[{signature}]]></MsgSignature>
  <TimeStamp>{timestamp}</TimeStamp>
  <Nonce><![CDATA[{nonce}]]></Nonce>
</xml>"""
            return response, 200, {"Content-Type": "application/xml"}

    elif request.method == "HEAD":
            return "", 200

    except Exception as e:
        print("[ERROR]", e)
        return "error", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
