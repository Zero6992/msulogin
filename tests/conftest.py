"""Shared test harness for the MSU Login Launcher.

Nothing here talks to the network. Every outbound call the app makes goes
through ``login.post_r`` / ``login.get_r``; the ``upstream`` fixture replaces
both with an in-memory fake that records each call, and an autouse tripwire
fails any test that reaches ``requests`` or opens a socket anyway.

Run (in a no-network namespace):
    unshare -rn env PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider tests/
"""
import os
import pathlib
import socket
import sys
from collections import namedtuple

# Environment must be fixed BEFORE `import login` (limits are read at import).
os.environ.update(
    COOKIE_SECURE="0",
    LOG_LEVEL="WARNING",
    RATE_LIMIT="30/minute",
    MAX_SESSIONS="1000",
    STEP1_PER_ADDRESS_LIMIT="5/minute",
    STEP1_PER_ADDRESS_GLOBAL_LIMIT="30/minute",
    RATELIMIT_STORAGE_URI="memory://",
)
for _name in (
    "TRUST_PROXY_FIX", "FORCE_HTTPS", "ALLOWED_ORIGINS", "MAX_BODY_BYTES",
    "MAX_SESSIONS_PER_CLIENT", "SESSION_MAX_LIFETIME_SECONDS",
):
    os.environ.pop(_name, None)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402
import requests  # noqa: E402
from eth_account import Account  # noqa: E402
from eth_account.messages import encode_defunct  # noqa: E402

import login  # noqa: E402

ORIGIN = {"Origin": "http://localhost"}
DEFAULT_IP = "198.51.100.10"


def make_jwt(n):
    """Three base64url segments of 8+ chars, so login.JWT_RE and the S5 token
    pattern both accept it."""
    return f"hdr{n:05d}xx.pay{n:05d}xx.sig{n:05d}xx"


# --------------------------------------------------------------------------
# Network tripwire + clean state (autouse)
# --------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolation(monkeypatch):
    login.user_sessions.clear()
    login.limiter.reset()

    attempts = []

    def tripwire(*args, **kwargs):
        attempts.append(args[:2])
        raise RuntimeError("network access attempted during a test")

    monkeypatch.setattr(login.requests, "post", tripwire)
    monkeypatch.setattr(login.requests, "get", tripwire)
    monkeypatch.setattr(requests.Session, "request", tripwire)
    monkeypatch.setattr(socket.socket, "connect", tripwire)
    monkeypatch.setattr(socket, "getaddrinfo", tripwire)

    yield

    login.user_sessions.clear()
    assert not attempts, f"test reached the network: {attempts}"


# --------------------------------------------------------------------------
# Fake msu.io
# --------------------------------------------------------------------------

Call = namedtuple("Call", "method name url data cookies headers")

_ROUTES = (  # (url suffix, endpoint name)
    ("/web/can-signin", "can-signin"),
    ("/web/message", "message"),
    ("/web/signin-wallet", "signin-wallet"),
    ("/web/token/verify", "token-verify"),
    ("/web/token/refresh-web", "refresh-web"),
    ("/game/message", "game-message"),
    ("/api/mfa/otp/verify", "otp-verify"),
    ("/web/token/webtogame", "webtogame"),
)

_MFA_REQUIRED = {
    "code": 7,
    "message": "MFA OTP required",
    "details": [{"code": "ACCOUNT_ERROR_CODE_REQUIRE_MFA_OTP"}],
}


class FakeUpstream:
    """In-memory stand-in for msu.io. Defaults model a wallet without 2FA."""

    def __init__(self):
        self.calls = []
        self.hooks = {}            # endpoint name -> callable run before replying
        self.unreachable = set()   # endpoint names that return (None, None, None)
        self.nonce = 0
        self.valid_otp = "123456"
        self.otp_verified = False
        self.gt = "dGVzdC1ndA=="
        # Behaviour switches
        self.signin_mfa = False        # signin-wallet demands mfaCode
        self.signin_error = False      # signin-wallet refuses the signature
        self.signin_data = {"msu_wat": make_jwt(1)}
        self.launch_mfa = False        # webtogame demands a prior OTP verify
        self.webtogame_result = None   # explicit (result, cookies, status)
        self.game_cookies = {}         # cookies set by game/message
        self.account_address = None    # None = echo requested address
        self.good_tokens = None        # None = token/verify accepts any token

    # -- recording helpers -------------------------------------------------
    def of(self, name):
        return [c for c in self.calls if c.name == name]

    def count(self, name=None):
        return len(self.calls) if name is None else len(self.of(name))

    # -- login.post_r / login.get_r replacements -----------------------------
    def post_r(self, url, data, cookies=None, headers=None):
        return self._handle("POST", url, data, cookies, headers)

    def get_r(self, url, cookies=None, headers=None):
        return self._handle("GET", url, None, cookies, headers)

    def _handle(self, method, url, data, cookies, headers):
        name = "account" if "/web/account/" in url else next(
            (n for suffix, n in _ROUTES if url.endswith(suffix)), None)
        assert name, f"unexpected upstream URL {url}"
        self.calls.append(Call(method, name, url, dict(data or {}),
                               dict(cookies or {}), dict(headers or {})))
        if name in self.hooks:
            self.hooks[name]()
        if name in self.unreachable:
            return None, None, None
        return getattr(self, "_" + name.replace("-", "_"))(url, data or {}, headers or {})

    # -- endpoints -----------------------------------------------------------
    def _can_signin(self, url, data, headers):
        return {"code": 0}, {"edge": "1"}, 200

    def _account(self, url, data, headers):
        requested = url.rsplit("/", 1)[-1]
        address = requested if self.account_address is None else self.account_address
        return {"account": {"address": address}}, {}, 200

    def _message(self, url, data, headers):
        self.nonce += 1
        return {"message": f"Sign in to MSU, nonce {self.nonce}"}, {}, 200

    def _signin_wallet(self, url, data, headers):
        if self.signin_mfa and data.get("mfaCode") != self.valid_otp:
            return dict(_MFA_REQUIRED), {}, 400
        if self.signin_error:
            return {"code": 3, "message": "signin refused"}, {}, 400
        return {"code": 0, "data": dict(self.signin_data)}, {}, 200

    def _token_verify(self, url, data, headers):
        token = headers.get("Authorization", "").removeprefix("Bearer ")
        if self.good_tokens is None or token in self.good_tokens:
            return {"address": "0xabc"}, {}, 200
        return {"message": "invalid token"}, {}, 401

    def _refresh_web(self, url, data, headers):
        return {}, {}, 200

    def _game_message(self, url, data, headers):
        self.nonce += 1
        return {"message": f"Launch the game, nonce {self.nonce}"}, dict(self.game_cookies), 200

    def _otp_verify(self, url, data, headers):
        if data.get("otpCode") == self.valid_otp:
            self.otp_verified = True
            return {"verified": True}, {}, 200
        return {"verified": False, "message": "invalid code"}, {}, 400

    def _webtogame(self, url, data, headers):
        if self.webtogame_result is not None:
            return self.webtogame_result
        if self.launch_mfa and not self.otp_verified:
            return dict(_MFA_REQUIRED), {}, 400
        return {"data": {"gt": self.gt}}, {}, 200


@pytest.fixture
def upstream(monkeypatch):
    fake = FakeUpstream()
    monkeypatch.setattr(login, "post_r", fake.post_r)
    monkeypatch.setattr(login, "get_r", fake.get_r)
    return fake


# --------------------------------------------------------------------------
# Wallets, browsers, clock
# --------------------------------------------------------------------------

class Wallet:
    """Throwaway key pair; never holds anything of value."""

    def __init__(self):
        self.acct = Account.create()
        self.address = self.acct.address.lower()

    def sign(self, message):
        sig = Account.sign_message(encode_defunct(text=message),
                                   private_key=self.acct.key).signature.hex()
        return sig if sig.startswith("0x") else "0x" + sig


class Browser:
    """One cookie jar plus a fixed source IP, driving POST /api/launch."""

    def __init__(self, ip=DEFAULT_IP):
        self.ip = ip
        self.client = login.app.test_client()

    def raw(self, **kwargs):
        headers = {**ORIGIN, **kwargs.pop("headers", {})}
        return self.client.post("/api/launch", headers=headers,
                                environ_base={"REMOTE_ADDR": self.ip}, **kwargs)

    def call(self, **body):
        return self.raw(json=body)

    def step1(self, wallet):
        return self.call(step=1, address=wallet.address)

    def step2(self, wallet, message, **extra):
        return self.call(step=2, signature1=wallet.sign(message), **extra)

    def step3(self):
        return self.call(step=3)

    def step4(self, wallet, message, **extra):
        return self.call(step=4, signature2=wallet.sign(message), **extra)

    @property
    def sid(self):
        cookie = self.client.get_cookie(login.SESSION_COOKIE_NAME)
        return cookie.value if cookie else None

    def sign_in(self, wallet):
        """Steps 1-2; returns (and remembers) the step-1 message."""
        self.msg1 = self.step1(wallet).get_json()["message"]
        assert self.step2(wallet, self.msg1).get_json()["success"] is True
        return self.msg1

    def sign_in_to_step3(self, wallet):
        """Steps 1-3; returns (and remembers) the step-3 (game) message."""
        self.sign_in(wallet)
        self.msg3 = self.step3().get_json()["message"]
        return self.msg3


@pytest.fixture
def jwt():
    return make_jwt


@pytest.fixture
def new_wallet():
    return Wallet


@pytest.fixture
def wallet():
    return Wallet()


@pytest.fixture
def new_browser():
    return Browser


@pytest.fixture
def browser():
    return Browser()


class FakeClock:
    """Stands in for the `time` module inside login (it only uses time.time)."""

    def __init__(self, now=1_000_000.0):
        self.now = now

    def time(self):
        return self.now

    monotonic = time

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(login, "time", fake)
    return fake
