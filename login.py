from flask import Flask, render_template, request, jsonify, make_response
import os
import secrets
import time
import requests
import re

from eth_account import Account
from eth_account.messages import encode_defunct

app = Flask(__name__)

# Sessions keyed by server-issued opaque ID (delivered via HttpOnly cookie),
# never by the client-supplied wallet address.
user_sessions = {}
SESSION_TTL_SECONDS = 15 * 60
SESSION_COOKIE_NAME = "msu_session"
# Disable only for plain-HTTP local dev: COOKIE_SECURE=0
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "1") != "0"
JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})(?![A-Za-z0-9_-])"
)
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
SIGNATURE_RE = re.compile(r"^0x[0-9a-fA-F]{130}$")


def verify_signature(address, message, signature):
    """Recover signer from an EIP-191 personal_sign signature and compare."""
    if not (isinstance(address, str) and isinstance(message, str) and isinstance(signature, str)):
        return False
    try:
        recovered = Account.recover_message(
            encode_defunct(text=message), signature=signature
        )
        return recovered.lower() == address.lower()
    except Exception:
        return False
DEFAULT_HEADERS = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6",
    "Cache-Control": "no-cache",
    "Content-Type": "application/json",
    "Origin": "https://msu.io",
    "Pragma": "no-cache",
    "Priority": "u=1, i",
    "Referer": "https://msu.io/maplestoryn/gamestatus/ranking",
    "Sec-CH-UA": "\"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"144\", \"Google Chrome\";v=\"144\"",
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": "\"Windows\"",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/144.0.0.0 Safari/537.36"
    ),
}


def cleanup_expired_sessions():
    now = time.time()
    for address, state in list(user_sessions.items()):
        created_at = state.get("created_at", 0)
        if now - created_at > SESSION_TTL_SECONDS:
            user_sessions.pop(address, None)


def post_r(url, data, cookies=None, headers=None):
    """Helper function to make POST requests."""
    try:
        merged_headers = dict(DEFAULT_HEADERS)
        if headers:
            merged_headers.update(headers)
        response = requests.post(
            url, json=data, cookies=cookies, headers=merged_headers,
            timeout=10, allow_redirects=False,
        )
        return response.json(), response.cookies.get_dict(), response.status_code
    except Exception as e:
        print(f"Error: {e}")
        return None, None, None


def get_r(url, cookies=None, headers=None):
    """Helper function to make GET requests."""
    try:
        merged_headers = dict(DEFAULT_HEADERS)
        if headers:
            merged_headers.update(headers)
        response = requests.get(
            url, cookies=cookies, headers=merged_headers,
            timeout=10, allow_redirects=False,
        )
        return response.json(), response.cookies.get_dict(), response.status_code
    except Exception as e:
        print(f"Error: {e}")
        return None, None, None


def merge_cookies(old_cookies, new_cookies):
    merged = dict(old_cookies or {})
    for key, value in (new_cookies or {}).items():
        if value is not None and value != "":
            merged[key] = value
    return merged


def read_nested(data, key):
    if isinstance(data, dict):
        if key in data:
            return data.get(key)
        nested = data.get("data")
        if isinstance(nested, dict):
            return nested.get(key)
    return None


def inject_manual_jwt(cookies, msu_wat=None, msu_wrt=None):
    updated = dict(cookies or {})
    if isinstance(msu_wat, str) and msu_wat.strip():
        updated["msu_wat"] = msu_wat.strip()
    if isinstance(msu_wrt, str) and msu_wrt.strip():
        updated["msu_wrt"] = msu_wrt.strip()
    return updated


def result_message(result):
    if isinstance(result, dict):
        msg = result.get("message")
        if isinstance(msg, str):
            return msg
    return ""


def extract_error_message(result, status_code=None):
    parts = []
    msg = result_message(result).strip()
    if msg:
        parts.append(msg)

    if isinstance(result, dict):
        details = result.get("details")
        if isinstance(details, list) and details and isinstance(details[0], dict):
            detail_code = details[0].get("code")
            if detail_code:
                parts.append(str(detail_code))
        code = result.get("code")
        if code is not None:
            parts.append(f"code {code}")

    if parts:
        # deduplicate while preserving order
        dedup = []
        seen = set()
        for p in parts:
            if p not in seen:
                seen.add(p)
                dedup.append(p)
        return " | ".join(dedup)

    if isinstance(status_code, int):
        return f"HTTP {status_code}"
    return "Unknown error"


def is_error_result(result, status_code):
    if isinstance(status_code, int) and status_code >= 400:
        return True
    if isinstance(result, dict):
        code = result.get("code")
        if isinstance(code, int) and code != 0:
            return True
        msg = result_message(result).strip().lower()
        if "too many sign up request" in msg:
            return True
    return False


def collect_jwt_candidates(obj):
    candidates = []
    seen = set()

    def push(token):
        if token and token not in seen:
            seen.add(token)
            candidates.append(token)

    def walk(value):
        if isinstance(value, dict):
            for nested in value.values():
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)
        elif isinstance(value, str):
            for match in JWT_RE.finditer(value):
                push(match.group(1))

    walk(obj)
    return candidates


def verify_auth_jwt(jwt_token, cookies=None):
    if not isinstance(jwt_token, str) or not jwt_token:
        return False
    headers = {"Authorization": f"Bearer {jwt_token}"}
    result, _, status_code = post_r(
        "https://msu.io/maplestoryn/api/web/token/verify", {}, cookies, headers=headers
    )
    if status_code and status_code >= 400:
        return False
    address = read_nested(result, "address")
    return isinstance(address, str) and len(address) > 0


def pick_auth_jwt(candidates, cookies=None):
    for token in candidates:
        if verify_auth_jwt(token, cookies):
            return token
    return None


def refresh_web_token(cookies, auth_jwt=None):
    """
    Best-effort refresh call used by official frontend retry flow.
    It may return wat/wrt in body, and/or set cookies.
    """
    request_data = {}
    headers = {}
    if isinstance(auth_jwt, str) and auth_jwt:
        headers["Authorization"] = f"Bearer {auth_jwt}"

    result, refresh_cookies, _ = post_r(
        "https://msu.io/maplestoryn/api/web/token/refresh-web",
        request_data,
        cookies,
        headers=headers or None,
    )

    merged = merge_cookies(cookies, refresh_cookies)
    wat = read_nested(result, "wat") or read_nested(result, "msu_wat")
    wrt = read_nested(result, "wrt") or read_nested(result, "msu_wrt")
    merged = inject_manual_jwt(merged, msu_wat=wat, msu_wrt=wrt)
    return merged


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/launch', methods=['POST'])
def launch():
    """Single endpoint that handles all the internal API calls."""
    try:
        cleanup_expired_sessions()

        data = request.get_json(silent=True) or {}
        public_address = data.get('address')
        signature1 = data.get('signature1')
        signature2 = data.get('signature2')
        try:
            step = int(data.get('step'))
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "Invalid step"}), 400

        # Step 1 accepts the address from the body and creates a fresh server
        # session. Steps 2-4 must present the session cookie issued at step 1;
        # the address is read from server state, never re-trusted from the body.
        if step == 1:
            if not isinstance(public_address, str) or not ADDRESS_RE.match(public_address.strip()):
                return jsonify({"success": False, "error": "Invalid wallet address"}), 400
            public_address = public_address.strip().lower()
            sid = None
            state = {}
            user_cookies = {}
            auth_jwt = None
            jwt_candidates = []
        else:
            sid = request.cookies.get(SESSION_COOKIE_NAME)
            state = user_sessions.get(sid) if sid else None
            if not state:
                return jsonify({"success": False, "error": "Session expired or missing"}), 401
            public_address = state["address"]
            user_cookies = state.get("cookies", {})
            auth_jwt = state.get("auth_jwt")
            jwt_candidates = list(state.get("jwt_candidates", []))

        # Step 1: can-signin, account lookup, and get web message.
        if step == 1:
            # Follow official frontend call order.
            can_signin_result, can_signin_cookies, _ = post_r(
                "https://msu.io/maplestoryn/api/web/can-signin", {}
            )
            if can_signin_result is None:
                return jsonify({"success": False, "error": "Can't sign in"}), 400

            pre_cookies = merge_cookies(user_cookies, can_signin_cookies)

            # Best-effort account lookup; official frontend does this before requesting message.
            account_result, account_cookies, _ = get_r(
                f"https://msu.io/maplestoryn/api/web/account/{public_address}",
                pre_cookies,
            )
            pre_cookies = merge_cookies(pre_cookies, account_cookies)

            # Use canonical address from account profile when available.
            account_obj = account_result.get("account") if isinstance(account_result, dict) else None
            login_address = (
                account_obj.get("address")
                if isinstance(account_obj, dict) and isinstance(account_obj.get("address"), str)
                else public_address
            )
            if isinstance(login_address, str):
                login_address = login_address.strip() or public_address
            else:
                login_address = public_address

            request_data = {"address": login_address}
            result, message_cookies, _ = post_r(
                "https://msu.io/maplestoryn/api/web/message",
                request_data,
                pre_cookies,
            )
            pre_cookies = merge_cookies(pre_cookies, message_cookies)

            if not (result and "message" in result):
                return jsonify({"success": False, "error": "Failed to get message"}), 400

            # Mint a fresh server-side session ID and bind it to the address.
            # The address is stored server-side so the client cannot pivot
            # to another user's session by changing the request body.
            sid = secrets.token_urlsafe(32)
            user_sessions[sid] = {
                "address": public_address,
                "cookies": pre_cookies,
                "created_at": time.time(),
                "auth_jwt": None,
                "jwt_candidates": [],
                "login_address": login_address,
                "step1_message": result["message"],
                "step3_message": None,
            }

            resp = make_response(jsonify(
                {"success": True, "message": result["message"], "login_address": login_address}
            ))
            resp.set_cookie(
                SESSION_COOKIE_NAME, sid,
                httponly=True, secure=COOKIE_SECURE, samesite="Strict",
                max_age=SESSION_TTL_SECONDS,
            )
            return resp

        # Step 2: signin-wallet
        elif step == 2:
            if not isinstance(signature1, str) or not SIGNATURE_RE.match(signature1.strip()):
                return jsonify({"success": False, "error": "Invalid signature1"}), 400
            signature1 = signature1.strip()

            # Verify the signature was produced by the session's wallet
            # over the exact message MSU asked us to sign at step 1.
            step1_message = state.get("step1_message")
            if not step1_message or not verify_signature(public_address, step1_message, signature1):
                return jsonify({"success": False, "error": "Signature does not match wallet"}), 403

            login_address = state.get("login_address") or public_address
            request_data = {
                "address": login_address,
                "signature": signature1,
                "walletType": "WALLET_TYPE_METAMASK",
            }
            result, cookies, status_code = post_r(
                "https://msu.io/maplestoryn/api/web/signin-wallet", request_data, user_cookies
            )

            if result is None:
                return jsonify({"success": False, "error": "Failed to sign in"}), 400

            primary_result = result
            primary_cookies = cookies
            primary_status = status_code
            retry_result = None
            retry_status = None

            # Store cookies for this user (og behavior + merge).
            merged = merge_cookies(user_cookies, cookies)
            step2_error = is_error_result(result, status_code)

            # Fallback: if JWT is in body, capture it.
            msu_wat = (
                read_nested(result, "msu_wat")
                or read_nested(result, "wat")
                or read_nested(result, "accessToken")
                or read_nested(result, "access_token")
                or read_nested(result, "jwt")
                or read_nested(result, "token")
            )
            msu_wrt = (
                read_nested(result, "msu_wrt")
                or read_nested(result, "wrt")
                or read_nested(result, "refreshToken")
                or read_nested(result, "refresh_token")
            )
            merged = inject_manual_jwt(merged, msu_wat=msu_wat, msu_wrt=msu_wrt)
            jwt_candidates.extend(collect_jwt_candidates(result))
            if merged.get("msu_wat"):
                jwt_candidates.insert(0, merged.get("msu_wat"))
            if merged.get("msu_wrt"):
                jwt_candidates.append(merged.get("msu_wrt"))
            # keep unique & small list
            uniq = []
            seen = set()
            for token in jwt_candidates:
                if token and token not in seen:
                    seen.add(token)
                    uniq.append(token)
            jwt_candidates = uniq[:12]

            # Do not issue extra auth requests when upstream Step2 is already an error.
            if not step2_error:
                if not auth_jwt and merged.get("msu_wat"):
                    auth_jwt = merged.get("msu_wat")
                if not auth_jwt:
                    auth_jwt = pick_auth_jwt(jwt_candidates, merged)
                merged = refresh_web_token(merged, auth_jwt=auth_jwt)
                if not auth_jwt and merged.get("msu_wat"):
                    auth_jwt = merged.get("msu_wat")

            user_sessions[sid].update({
                "cookies": merged,
                "created_at": time.time(),
                "auth_jwt": auth_jwt,
                "jwt_candidates": jwt_candidates,
                "login_address": login_address,
            })

            return jsonify(
                {
                    "success": True,
                    "has_jwt": bool(merged.get("msu_wat") or merged.get("msu_wrt")),
                    "has_auth_jwt": bool(auth_jwt),
                    "step2_message": result_message(result),
                    "step2_error": step2_error,
                    "step2_error_detail": extract_error_message(result, status_code),
                    "step2_status": status_code,
                    "step2_result_keys": list(result.keys()) if isinstance(result, dict) else [],
                    "step2_cookie_keys": sorted(list((cookies or {}).keys())),
                    "step2_primary_error_detail": extract_error_message(primary_result, primary_status),
                    "step2_login_address": login_address,
                    "step2_retry_error_detail": (
                        extract_error_message(retry_result, retry_status)
                        if retry_result is not None
                        else ""
                    ),
                }
            )

        # Step 3: get game message
        elif step == 3:
            login_address = state.get("login_address") or public_address
            request_data = {"address": login_address}
            result, cookies, _ = post_r(
                "https://msu.io/maplestoryn/api/game/message", request_data, user_cookies
            )

            # Minimal JWT fix: merge step3 cookies as well.
            if cookies:
                merged = merge_cookies(user_cookies, cookies)
                if not auth_jwt and merged.get("msu_wat"):
                    auth_jwt = merged.get("msu_wat")
                merged = refresh_web_token(merged, auth_jwt=auth_jwt)
                if not auth_jwt and merged.get("msu_wat"):
                    auth_jwt = merged.get("msu_wat")
                user_sessions[sid].update({
                    "cookies": merged,
                    "created_at": time.time(),
                    "auth_jwt": auth_jwt,
                    "jwt_candidates": jwt_candidates,
                    "login_address": login_address,
                })
                user_cookies = merged

            if result and "message" in result:
                # Remember the exact message so we can verify signature2 at step 4.
                user_sessions[sid]["step3_message"] = result["message"]
                return jsonify({"success": True, "message": result["message"]})
            else:
                return jsonify({"success": False, "error": "Failed to get game message"}), 400

        # Step 4: web to game token and generate launch command
        elif step == 4:
            if not isinstance(signature2, str) or not SIGNATURE_RE.match(signature2.strip()):
                return jsonify({"success": False, "error": "Invalid signature2"}), 400
            signature2 = signature2.strip()

            step3_message = state.get("step3_message")
            if not step3_message or not verify_signature(public_address, step3_message, signature2):
                return jsonify({"success": False, "error": "Signature does not match wallet"}), 403

            # Optional manual JWT from frontend.
            manual_msu_wat = data.get("msu_wat") or data.get("jwt")
            manual_msu_wrt = data.get("msu_wrt")
            user_cookies = inject_manual_jwt(
                user_cookies, msu_wat=manual_msu_wat, msu_wrt=manual_msu_wrt
            )
            if isinstance(manual_msu_wat, str) and manual_msu_wat.strip():
                auth_jwt = manual_msu_wat.strip()
                if auth_jwt not in jwt_candidates:
                    jwt_candidates.insert(0, auth_jwt)
            if not auth_jwt and user_cookies.get("msu_wat"):
                auth_jwt = user_cookies.get("msu_wat")
            if not auth_jwt:
                auth_jwt = pick_auth_jwt(jwt_candidates, user_cookies)
            user_cookies = refresh_web_token(user_cookies, auth_jwt=auth_jwt)
            if not auth_jwt and user_cookies.get("msu_wat"):
                auth_jwt = user_cookies.get("msu_wat")

            headers = {}
            if auth_jwt:
                headers["Authorization"] = f"Bearer {auth_jwt}"

            request_data = {"signature": signature2}
            result, cookies, _ = post_r(
                "https://msu.io/maplestoryn/api/web/token/webtogame",
                request_data,
                user_cookies,
                headers=headers or None,
            )

            # If JWT missing, try alternate verified candidates once.
            if (
                "Jwt is missing" in result_message(result)
                and jwt_candidates
            ):
                alt_auth = pick_auth_jwt(jwt_candidates, user_cookies)
                if alt_auth and alt_auth != auth_jwt:
                    auth_jwt = alt_auth
                    headers = {"Authorization": f"Bearer {auth_jwt}"}
                    result, cookies, _ = post_r(
                        "https://msu.io/maplestoryn/api/web/token/webtogame",
                        request_data,
                        user_cookies,
                        headers=headers,
                    )

            # Keep latest cookies for retry diagnostics.
            if cookies:
                merged = merge_cookies(user_cookies, cookies)
                user_sessions[sid].update({
                    "cookies": merged,
                    "created_at": time.time(),
                    "auth_jwt": auth_jwt,
                    "jwt_candidates": jwt_candidates,
                })

            gt = read_nested(result, "gt")
            if isinstance(gt, str) and gt:
                command = (
                    f"msul://launch/ -mode:launch -game:'106690@d811' "
                    f"-passarg:'{{\"gt\":\"{gt}\"}}' "
                    "-position:'GameWeb|https://msu.io/maplestoryn/' "
                    f"-architectureplatform:'none' -timestamp:{int(time.time())} -language:'en-US'"
                )

                # Clean up stored cookies
                if sid in user_sessions:
                    del user_sessions[sid]

                resp = make_response(jsonify({"success": True, "command": command}))
                resp.delete_cookie(SESSION_COOKIE_NAME)
                return resp
            else:
                error_msg = extract_error_message(result)
                return jsonify({"success": False, "error": f"Failed to get game token: {error_msg}"}), 400

        else:
            return jsonify({"success": False, "error": "Invalid step"}), 400

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


if __name__ == '__main__':
    host = '127.0.0.1'
    port = 51222
    try:
        from waitress import serve
        print(f" * Serving with waitress on http://{host}:{port}")
        serve(app, host=host, port=port)
    except ImportError:
        print(" * waitress not installed, falling back to Flask (debug off)")
        print("   pip install waitress  # recommended for production")
        app.run(host=host, port=port, debug=False, use_reloader=False)
