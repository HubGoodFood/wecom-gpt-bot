@app.route("/wechat_kf_callback", methods=["GET", "POST"])
def wechat_kf():
    if request.method == "GET":
        # 企业微信 GET 验证回调地址
        msg_signature = request.args.get("msg_signature")
        timestamp = request.args.get("timestamp")
        nonce = request.args.get("nonce")
        echostr = request.args.get("echostr") # 这是加密的echostr

        if not all([msg_signature, timestamp, nonce, echostr]):
            print("❌ GET 请求缺少参数 (wechat_kf)")
            return "Missing parameters for GET verification", 400
        try:
            # 使用 decrypt_message 方法来验证签名并解密 echostr
            decrypted_echostr = crypto.decrypt_message(echostr, msg_signature, timestamp, nonce)
            print("✅ URL 验证成功 (wechat_kf)")
            return decrypted_echostr # 必须返回解密后的 echostr 明文
        except Exception as e: # wechatpy 可能会抛出 InvalidSignatureException 等
            print(f"❌ URL 验证失败 (wechat_kf): {e}")
            traceback.print_exc()
            return "Verification failed", 403 # 返回 403 表示验证失败

    elif request.method == "POST":
        # ... 您现有的 POST 请求处理逻辑 ...
        # (这部分逻辑在您上次提供的 wecom_openkf_gpt_bot (1).py 文件中，
        # 我根据您的要求修改过，以尝试实现两步消息处理流程)
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

# 其余的函数如 get_wecom_access_token, fetch_and_respond, ask_gpt 等保持您上一版本中的不变。
# ... (确保这些函数定义存在且正确)
