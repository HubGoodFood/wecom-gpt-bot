from flask import Flask, request

app = Flask(__name__)

@app.route("/", methods=["GET", "POST", "HEAD"])
def wechat_callback():
    print("🚨 wechat_callback 被触发")
    print("🔍 method:", request.method)
    return "OK", 200

if __name__ == "__main__":
    print("✅ 极简版 Flask 启动成功")
    app.run(host="0.0.0.0", port=10000)