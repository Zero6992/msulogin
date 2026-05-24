from flask import Flask, render_template, request, jsonify
import time
import requests

app = Flask(__name__)

# Store sessions per user address
user_sessions = {}

def post_r(url, data, cookies=None):
    """Helper function to make POST requests"""
    try:
        response = requests.post(url, json=data, cookies=cookies, timeout=10)
        return response.json(), response.cookies.get_dict()
    except Exception as e:
        print(f"Error: {e}")
        return None, None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/launch', methods=['POST'])
def launch():
    """Single endpoint that handles all the internal API calls"""
    try:
        data = request.json
        public_address = data.get('address')
        signature1 = data.get('signature1')
        signature2 = data.get('signature2')
        step = data.get('step')
        
        # Get stored cookies for this user
        user_cookies = user_sessions.get(public_address, {})
        
        # Step 1: can-signin and get web message
        if step == 1:
            request_data = {"accountAddress": public_address}
            result, _ = post_r("https://msu.io/maplestoryn/api/web/can-signin", request_data)
            
            if result is None:
                return jsonify({"success": False, "error": "Can't sign in"}), 400
            
            request_data = {"address": public_address}
            result, _ = post_r("https://msu.io/maplestoryn/api/web/message", request_data)
            
            if result and "message" in result:
                return jsonify({"success": True, "message": result["message"]})
            else:
                return jsonify({"success": False, "error": "Failed to get message"}), 400
        
        # Step 2: signin-wallet
        elif step == 2:
            request_data = {
                "address": public_address,
                "signature": signature1,
                "walletType": "WALLET_TYPE_METAMASK",
            }
            result, cookies = post_r("https://msu.io/maplestoryn/api/web/signin-wallet", request_data)
            
            if result is None:
                return jsonify({"success": False, "error": "Failed to sign in"}), 400
            
            # Store cookies for this user
            if cookies:
                user_sessions[public_address] = cookies
            
            return jsonify({"success": True})
        
        # Step 3: get game message
        elif step == 3:
            request_data = {"address": public_address}
            result, _ = post_r("https://msu.io/maplestoryn/api/game/message", request_data, user_cookies)
            
            if result and "message" in result:
                return jsonify({"success": True, "message": result["message"]})
            else:
                return jsonify({"success": False, "error": "Failed to get game message"}), 400
        
        # Step 4: web to game token and generate launch command
        elif step == 4:
            request_data = {"signature": signature2}
            result, _ = post_r("https://msu.io/maplestoryn/api/web/token/webtogame", request_data, user_cookies)
            
            if result and 'gt' in result:
                command = (
                    f"msul://launch/ -mode:launch -game:'106690@d811' "
                    f"-passarg:'{{\"gt\":\"{result['gt']}\"}}' "
                    "-position:'GameWeb|https://msu.io/maplestoryn/' "
                    f"-architectureplatform:'none' -timestamp:{int(time.time())} -language:'en-US'"
                )
                
                # Clean up stored cookies
                if public_address in user_sessions:
                    del user_sessions[public_address]
                
                return jsonify({"success": True, "command": command})
            else:
                error_msg = result.get('message', 'Unknown error') if result else 'No response'
                return jsonify({"success": False, "error": f"Failed to get game token: {error_msg}"}), 400
        
        else:
            return jsonify({"success": False, "error": "Invalid step"}), 400
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',  # Listen on all network interfaces
        port=51222,        # Port number
        debug=True       # Set to False for production
    )