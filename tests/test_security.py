"""Regression tests for the reported issues S1-S9, plus the behaviour that
must NOT change. Each test encodes the FIXED behaviour; on the unfixed code a
failing test is the reproduction of the corresponding problem.

All upstream (msu.io) traffic is faked, see conftest.py.
"""
import ast
import logging
import pathlib
import subprocess
import sys
import threading

import pytest
import requests
from waitress.proxy_headers import proxy_headers_middleware
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.test import Client

import login

REPO = pathlib.Path(login.__file__).resolve().parent
ORIGIN = {"Origin": "http://localhost"}
SIG = "0x" + "11" * 65  # well-formed, never valid


def tiny(monkeypatch, **limits):
    """Shrink module limits for one test. raising=False so that a constant the
    fix introduces fails the test on behaviour, not on a setup AttributeError."""
    for name, value in limits.items():
        monkeypatch.setattr(login, name, value, raising=False)


# ==========================================================================
# Unchanged behaviour
# ==========================================================================

def test_happy_path_steps_1_to_4_return_command_and_drop_session(upstream, browser, wallet):
    r1 = browser.step1(wallet)
    j1 = r1.get_json()
    assert r1.status_code == 200 and j1["success"] is True
    assert j1["login_address"] == wallet.address
    assert browser.sid in login.user_sessions
    assert [c.name for c in upstream.calls] == ["can-signin", "account", "message"]

    j2 = browser.step2(wallet, j1["message"]).get_json()
    assert j2["success"] and j2["has_auth_jwt"] and not j2["step2_error"]

    j3 = browser.step3().get_json()
    assert j3["success"] is True

    r4 = browser.step4(wallet, j3["message"])
    command = r4.get_json()["command"]
    assert r4.status_code == 200
    assert command.startswith("msul://launch/ ")
    assert f'"gt":"{upstream.gt}"' in command
    assert login.user_sessions == {}


def test_step2_mfa_prompts_then_accepts_valid_code(upstream, browser, wallet):
    upstream.signin_mfa = True
    msg1 = browser.step1(wallet).get_json()["message"]

    first = browser.step2(wallet, msg1).get_json()
    assert first["mfa_required"] is True and first["step2_error"] is True
    assert first["has_auth_jwt"] is False

    second = browser.step2(wallet, msg1, mfa_code="123456").get_json()
    assert second["mfa_required"] is False and second["step2_error"] is False
    assert second["has_auth_jwt"] is True
    assert upstream.of("signin-wallet")[-1].data["mfaCode"] == "123456"


def test_step2_malformed_mfa_code_is_rejected_without_upstream_call(upstream, browser, wallet):
    msg1 = browser.step1(wallet).get_json()["message"]
    j = browser.step2(wallet, msg1, mfa_code="12").get_json()
    assert j["mfa_required"] is True
    assert upstream.count("signin-wallet") == 0


def test_step4_mfa_prompts_then_verifies_code_and_launches(upstream, browser, wallet):
    upstream.launch_mfa = True
    msg3 = browser.sign_in_to_step3(wallet)

    first = browser.step4(wallet, msg3).get_json()
    assert first["success"] is True and first["mfa_required"] is True
    assert "command" not in first
    assert browser.sid in login.user_sessions

    second = browser.step4(wallet, msg3, mfa_code="123456").get_json()
    assert second["command"].startswith("msul://launch/")
    assert upstream.of("otp-verify")[0].data["otpCode"] == "123456"


@pytest.mark.parametrize("step", [2, 4])
def test_signature_from_another_wallet_is_403(step, upstream, browser, wallet, new_wallet):
    impostor = new_wallet()
    msg3 = browser.sign_in_to_step3(wallet)
    if step == 2:
        r = browser.step2(impostor, browser.msg1)
    else:
        r = browser.step4(impostor, msg3)
    assert r.status_code == 403
    assert r.get_json()["error"] == "Signature does not match wallet"
    assert upstream.count("webtogame") == 0


@pytest.mark.parametrize("cookie", [None, "not-a-real-session-id"], ids=["no-cookie", "unknown-cookie"])
@pytest.mark.parametrize("step", [2, 3, 4])
def test_steps_2_to_4_without_valid_session_are_401(step, cookie, upstream, browser):
    if cookie:
        browser.client.set_cookie(login.SESSION_COOKIE_NAME, cookie)
    r = browser.call(step=step, signature1=SIG, signature2=SIG)
    assert r.status_code == 401
    assert r.get_json()["error"] == "Session expired or missing"
    assert upstream.count() == 0


@pytest.mark.parametrize("origin", ["https://evil.example", None], ids=["foreign-origin", "missing-origin"])
def test_post_with_bad_origin_is_403(origin, upstream, browser, wallet):
    if origin:
        r = browser.raw(headers={"Origin": origin}, json={"step": 1, "address": wallet.address})
    else:
        r = login.app.test_client().post("/api/launch", json={"step": 1, "address": wallet.address})
    assert r.status_code == 403
    assert upstream.count() == 0 and login.user_sessions == {}


# ==========================================================================
# S1: per-client session quota, reserve-before-upstream, lifetime
# ==========================================================================

def test_s1_client_cannot_hold_more_sessions_than_its_quota(monkeypatch, upstream, new_browser, new_wallet):
    tiny(monkeypatch, MAX_SESSIONS_PER_CLIENT=2)
    ip = "203.0.113.7"
    assert new_browser(ip).step1(new_wallet()).status_code == 200
    assert new_browser(ip).step1(new_wallet()).status_code == 200

    calls_before = upstream.count()
    refused = new_browser(ip).step1(new_wallet())

    assert refused.status_code == 429
    assert refused.get_json() == {"success": False, "error": "Too many active sessions"}
    assert upstream.count() == calls_before  # rejected before any outbound call
    assert len(login.user_sessions) == 2


def test_s1_one_noisy_client_cannot_lock_out_other_ips(monkeypatch, upstream, new_browser, new_wallet):
    tiny(monkeypatch, MAX_SESSIONS=5, MAX_SESSIONS_PER_CLIENT=2)
    attacker = [new_browser("203.0.113.7").step1(new_wallet()).status_code for _ in range(6)]

    victim = new_browser("198.51.100.99").step1(new_wallet())

    assert victim.status_code == 200
    assert attacker.count(200) <= 2


def test_s1_ipv6_clients_are_grouped_by_slash_64(monkeypatch, upstream, new_browser, new_wallet):
    tiny(monkeypatch, MAX_SESSIONS_PER_CLIENT=1)
    first = new_browser("2001:db8:1:2::1").step1(new_wallet())
    same_64 = new_browser("2001:db8:1:2:dead:beef:0:7").step1(new_wallet())
    other_64 = new_browser("2001:db8:1:3::1").step1(new_wallet())
    assert (first.status_code, same_64.status_code, other_64.status_code) == (200, 429, 200)


def test_s1_client_key_normalises_ipv6_and_keeps_other_values():
    def key(ip):
        with login.app.test_request_context("/", environ_base={"REMOTE_ADDR": ip}):
            return login.client_key()

    assert key("198.51.100.7") == "198.51.100.7"
    assert key("2001:db8:1:2::1") == key("2001:db8:1:2:ffff:ffff:ffff:ffff")
    assert key("2001:db8:1:2::1") != key("2001:db8:1:3::1")
    assert key("not-an-ip") == "not-an-ip"


def test_s1_new_step1_replaces_the_callers_previous_session(upstream, browser, new_wallet):
    assert browser.step1(new_wallet()).status_code == 200
    first_sid = browser.sid

    assert browser.step1(new_wallet()).status_code == 200

    assert first_sid not in login.user_sessions
    assert list(login.user_sessions) == [browser.sid]


def test_s1_full_pool_answers_503_before_any_outbound_call(monkeypatch, upstream, new_browser, new_wallet):
    tiny(monkeypatch, MAX_SESSIONS=1)
    assert new_browser("198.51.100.1").step1(new_wallet()).status_code == 200
    calls_before = upstream.count()

    r = new_browser("198.51.100.2").step1(new_wallet())

    assert (r.status_code, r.get_json()) == (503, {"success": False, "error": "Server busy"})
    assert upstream.count() == calls_before


@pytest.mark.parametrize("dead_endpoint", ["can-signin", "message"])
def test_s1_failed_step1_releases_its_reservation(dead_endpoint, monkeypatch, upstream, new_browser, new_wallet):
    tiny(monkeypatch, MAX_SESSIONS=1, MAX_SESSIONS_PER_CLIENT=1)
    upstream.unreachable.add(dead_endpoint)
    assert new_browser().step1(new_wallet()).status_code == 400
    assert login.user_sessions == {}

    upstream.unreachable.clear()
    assert new_browser().step1(new_wallet()).status_code == 200  # slot was not leaked


def test_s1_exception_during_step1_releases_the_reservation(monkeypatch, upstream, new_browser, new_wallet):
    tiny(monkeypatch, MAX_SESSIONS=1, MAX_SESSIONS_PER_CLIENT=1)

    def boom():
        raise RuntimeError("upstream client blew up")

    upstream.hooks["message"] = boom
    r = new_browser().step1(new_wallet())

    assert r.status_code == 500
    assert r.get_json()["error"] == "Internal error"
    assert login.user_sessions == {}  # nothing leaked, not even a pending placeholder

    del upstream.hooks["message"]
    assert new_browser().step1(new_wallet()).status_code == 200  # the single slot is usable again


def test_s1_concurrent_step1_from_one_client_cannot_exceed_its_quota(
        monkeypatch, upstream, new_browser, new_wallet):
    quota, total = 3, 10
    tiny(monkeypatch, MAX_SESSIONS_PER_CLIENT=quota)
    start = threading.Barrier(total)
    gate = threading.Event()
    refused = threading.Semaphore(0)
    codes, errors = [], []
    # Winners sit inside "upstream" (holding their reservation) until the losers are done.
    upstream.hooks["can-signin"] = lambda: gate.wait(timeout=10)

    def worker():
        try:
            b, w = new_browser("203.0.113.5"), new_wallet()
            start.wait(timeout=10)
            code = b.step1(w).status_code
            codes.append(code)
            if code != 200:
                refused.release()
        except Exception as exc:  # reported below, never swallowed
            errors.append(exc)
            refused.release()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(total)]
    try:
        for t in threads:
            t.start()
        for _ in range(total - quota):
            assert refused.acquire(timeout=10), "losers never finished"
        # Every reservation made so far is still held by an in-flight winner.
        assert len(login.user_sessions) == quota
        assert all(s["pending"] for s in login.user_sessions.values())
    finally:
        gate.set()
        for t in threads:
            t.join(timeout=10)

    assert errors == []
    assert sorted(codes) == [200] * quota + [429] * (total - quota)
    assert len(login.user_sessions) == quota
    assert not any(s["pending"] for s in login.user_sessions.values())  # all filled in, none leaked


@pytest.mark.parametrize("step", [2, 3, 4])
def test_s1_pending_reservation_is_not_a_usable_session(step, upstream, browser, clock):
    now = clock.time()
    login.user_sessions["pending-sid"] = {
        "client": browser.ip, "pending": True, "created_at": now, "born_at": now,
    }
    browser.client.set_cookie(login.SESSION_COOKIE_NAME, "pending-sid")

    r = browser.call(step=step, signature1=SIG, signature2=SIG)

    assert r.status_code == 401
    assert r.get_json()["error"] == "Session expired or missing"
    assert upstream.count() == 0


def test_s1_cleanup_evicts_idle_and_overlong_sessions(monkeypatch, clock):
    tiny(monkeypatch, SESSION_TTL_SECONDS=100, SESSION_MAX_LIFETIME_SECONDS=300)
    now = clock.time()
    login.user_sessions.update({
        "fresh": {"created_at": now, "born_at": now},
        "idle": {"created_at": now - 101, "born_at": now - 101},
        "active-but-too-old": {"created_at": now - 1, "born_at": now - 301},
    })

    login.cleanup_expired_sessions()

    assert set(login.user_sessions) == {"fresh"}


@pytest.mark.parametrize("refresher", ["step2", "step3", "step4"])
def test_s1_session_without_successful_signin_is_never_extended(
        refresher, monkeypatch, upstream, browser, wallet, clock):
    tiny(monkeypatch, SESSION_TTL_SECONDS=100, SESSION_MAX_LIFETIME_SECONDS=10_000)
    upstream.signin_error = True
    upstream.game_cookies = {"g": "1"}
    upstream.webtogame_result = ({"code": 5, "message": "denied"}, {"w": "1"}, 400)
    msg1 = browser.step1(wallet).get_json()["message"]
    assert browser.step2(wallet, msg1).get_json()["step2_error"] is True  # upstream refused
    msg3 = browser.step3().get_json()["message"]

    clock.advance(60)
    {
        "step2": lambda: browser.step2(wallet, msg1),
        "step3": lambda: browser.step3(),
        "step4": lambda: browser.step4(wallet, msg3),
    }[refresher]()
    clock.advance(60)  # 120 s after creation: past the 100 s TTL if nothing refreshed it

    assert browser.step2(wallet, msg1).status_code == 401


def test_s1_absolute_lifetime_caps_even_a_busy_signed_in_session(
        monkeypatch, upstream, browser, wallet, clock):
    tiny(monkeypatch, SESSION_TTL_SECONDS=100, SESSION_MAX_LIFETIME_SECONDS=250)
    upstream.game_cookies = {"g": "1"}  # step 3 refreshes the session whenever upstream sets cookies
    browser.sign_in(wallet)

    for _ in range(2):  # t = 90 and 180: active, within both limits
        clock.advance(90)
        assert browser.step3().status_code == 200
    clock.advance(90)  # t = 270: idle for only 90 s, but older than 250 s

    assert browser.step3().status_code == 401


# ==========================================================================
# S2: ProxyFix must not re-parse X-Forwarded-For after waitress
# ==========================================================================

def _status_codes_until_limit(xff_for):
    """Drive the app through waitress' proxy-header middleware (as in the
    Procfile) with RATE_LIMIT + 1 requests; no sockets involved."""
    app = proxy_headers_middleware(
        login.app, trusted_proxy="*", trusted_proxy_count=1,
        trusted_proxy_headers={"x-forwarded-for", "x-forwarded-proto"},
        clear_untrusted=True,
    )
    client = Client(app)
    limit = int(login.RATE_LIMIT.split("/")[0])
    codes = [
        client.post("/api/launch", json={"step": "x"},  # -> 400 Invalid step, cheap and local
                    headers={**ORIGIN, "X-Forwarded-For": xff_for(i)},
                    environ_base={"REMOTE_ADDR": "10.0.0.1"}).status_code  # 10.0.0.1 = the ingress
        for i in range(limit + 1)
    ]
    return limit, codes


@pytest.mark.parametrize("xff_for", [
    pytest.param(lambda i: "203.0.113.50", id="plain-hop"),
    pytest.param(lambda i: f'v{i}"z, 203.0.113.50', id="quoted-prefix-rotating"),
])
def test_s2_same_real_client_shares_one_rate_limit_bucket(xff_for):
    limit, codes = _status_codes_until_limit(xff_for)
    assert codes[:limit] == [400] * limit  # "Invalid step", all within the limit
    assert codes[limit] == 429


def test_s2_proxyfix_is_off_by_default():
    assert getattr(login, "PROXY_FIX_ENABLED", True) is False
    assert not isinstance(login.app.wsgi_app, ProxyFix)


def test_s2_proxyfix_is_opt_in_via_trust_proxy_fix():
    code = ("import login; "
            "print(login.PROXY_FIX_ENABLED, type(login.app.wsgi_app).__name__)")
    env = {"PATH": "", "TRUST_PROXY_FIX": "1", "COOKIE_SECURE": "0",
           "PYTHONDONTWRITEBYTECODE": "1"}
    out = subprocess.run([sys.executable, "-c", code], cwd=REPO, env=env,
                         capture_output=True, text=True, timeout=30)
    assert out.stdout.split() == ["True", "ProxyFix"], out.stderr[-500:]


# ==========================================================================
# S3: waitress pin
# ==========================================================================

def test_s3_requirements_pin_patched_waitress():
    pins = (REPO / "requirements.txt").read_text().split()
    assert "waitress==3.0.2" in pins


# ==========================================================================
# S4: request body cap
# ==========================================================================

def test_s4_oversized_body_is_413_and_never_reaches_upstream(upstream, browser, wallet):
    r = browser.raw(json={"step": 1, "address": wallet.address, "pad": "A" * 20_000})
    assert r.status_code == 413
    assert upstream.count() == 0 and login.user_sessions == {}


def test_s4_ordinary_sized_body_is_still_accepted(upstream, browser, wallet):
    r = browser.raw(json={"step": 1, "address": wallet.address, "pad": "A" * 1_000})
    assert r.status_code == 200


def test_s4_body_cap_defaults_to_16k_in_app_and_procfile():
    assert login.app.config.get("MAX_CONTENT_LENGTH") == 16384
    assert "--max-request-body-size=16384" in (REPO / "Procfile").read_text()


# ==========================================================================
# S5: manual step-4 tokens: format check and candidate cap
# ==========================================================================

BAD_MANUAL_TOKENS = [
    pytest.param("msu_wat", "bad token", id="space"),
    pytest.param("msu_wat", "tok\r\nSet-Cookie: x=1", id="crlf"),
    pytest.param("msu_wat", "x" * 4097, id="too-long"),
    pytest.param("msu_wat", 12345, id="number"),
    pytest.param("msu_wat", ["a"], id="list"),
    pytest.param("jwt", "semi;colon", id="jwt-alias"),
    pytest.param("msu_wrt", {"a": 1}, id="wrt-object"),
    pytest.param("msu_wrt", "quote'd", id="wrt-quote"),
]


@pytest.mark.parametrize("field,value", BAD_MANUAL_TOKENS)
def test_s5_malformed_manual_token_is_rejected_before_any_upstream_call(
        field, value, upstream, browser, wallet):
    msg3 = browser.sign_in_to_step3(wallet)
    calls_before = upstream.count()

    r = browser.step4(wallet, msg3, **{field: value})

    assert (r.status_code, r.get_json()) == (400, {"success": False, "error": "Invalid token"})
    assert upstream.count() == calls_before


@pytest.mark.parametrize("field,value", [
    pytest.param("msu_wat", "Abc_123-xyz.def.ghi", id="wat"),
    pytest.param("jwt", "Abc_123-xyz.def.ghi", id="jwt-alias"),
    pytest.param("msu_wrt", "Abc_123-xyz.def.ghi", id="wrt"),
    pytest.param("msu_wat", "  Abc_123-xyz.def.ghi  ", id="padded"),
    pytest.param("msu_wat", "x" * 4096, id="max-length"),
    pytest.param("msu_wat", "", id="empty-is-ignored"),
])
def test_s5_well_formed_or_empty_manual_token_still_launches(field, value, upstream, browser, wallet):
    msg3 = browser.sign_in_to_step3(wallet)
    r = browser.step4(wallet, msg3, **{field: value})
    assert r.get_json()["command"].startswith("msul://launch/")


def test_s5_candidate_cap_constant_is_three():
    assert getattr(login, "MAX_JWT_CANDIDATES", None) == 3


def test_s5_step2_keeps_at_most_three_candidates(upstream, browser, wallet, jwt):
    upstream.signin_data = {"msu_wat": jwt(1), "more": [jwt(n) for n in range(2, 9)]}
    browser.sign_in(wallet)
    assert len(login.user_sessions[browser.sid]["jwt_candidates"]) == 3


def test_s5_repeated_step4_cannot_grow_candidates_or_verify_calls(upstream, browser, wallet, jwt):
    upstream.good_tokens = set()  # nothing verifies, so every candidate gets tried
    upstream.webtogame_result = ({"code": 5, "message": "Jwt is missing"}, {"w": "1"}, 400)
    msg3 = browser.sign_in_to_step3(wallet)

    for n in range(10, 15):
        verifies_before = upstream.count("token-verify")
        browser.step4(wallet, msg3, msu_wat=jwt(n))
        assert len(login.user_sessions[browser.sid]["jwt_candidates"]) <= 3
        assert upstream.count("token-verify") - verifies_before <= 3


# ==========================================================================
# S6': per-wallet limits on step 1 (nonce churn / shared egress), counted only
# for requests that will actually reach msu.io
# ==========================================================================

@pytest.mark.parametrize("refusal", ["session-quota", "pool-full"])
def test_s6_requests_refused_before_upstream_do_not_burn_the_wallet_budget(
        refusal, monkeypatch, upstream, new_browser, new_wallet):
    victim = new_wallet()
    if refusal == "session-quota":
        tiny(monkeypatch, MAX_SESSIONS_PER_CLIENT=1)
        assert new_browser("203.0.113.7").step1(new_wallet()).status_code == 200  # fills the quota
        expected = (429, "Too many active sessions")
    else:
        tiny(monkeypatch, MAX_SESSIONS=1)
        assert new_browser("198.51.100.1").step1(new_wallet()).status_code == 200  # fills the pool
        expected = (503, "Server busy")
    calls_before = upstream.count()

    for _ in range(5):  # as many as the per-client wallet limit allows
        r = new_browser("203.0.113.7").step1(victim)
        assert (r.status_code, r.get_json()["error"]) == expected
    assert upstream.count() == calls_before

    login.user_sessions.clear()  # capacity is back
    # None of the refusals was counted: the same client still has its full budget...
    assert new_browser("203.0.113.7").step1(victim).status_code == 200
    login.user_sessions.clear()
    # ...and so does everybody else.
    assert new_browser("198.51.100.55").step1(victim).status_code == 200


def test_s6_sixth_step1_for_one_wallet_from_one_client_is_429_without_upstream_calls(
        upstream, browser, new_browser, new_wallet):
    victim = new_wallet()
    first_five = [browser.step1(victim).status_code for _ in range(5)]  # same browser: each replaces the last
    assert first_five == [200] * 5
    calls_before = upstream.count()

    r = browser.step1(victim)

    assert r.status_code == 429
    assert r.get_json() == {"success": False, "error": "Too many requests for this wallet"}
    assert upstream.count() == calls_before  # refused before any outbound call
    assert not [s for s in login.user_sessions.values() if s.get("pending")]  # reservation released

    other_wallet = browser.step1(new_wallet())
    assert other_wallet.status_code == 200  # other wallets are unaffected, and so is the session quota
    login.limiter.reset()
    assert browser.step1(victim).status_code == 200  # same storage as the IP limit


def test_s6_many_clients_can_each_start_step1_for_the_same_wallet(upstream, new_browser, new_wallet):
    victim = new_wallet()
    codes = [new_browser(f"198.51.100.{i}").step1(victim).status_code for i in range(1, 7)]
    assert codes == [200] * 6
    assert upstream.count("message") == 6


def test_s6_global_cap_stops_a_wallet_across_clients(monkeypatch, upstream, new_browser, new_wallet):
    tiny(monkeypatch, STEP1_PER_ADDRESS_GLOBAL_LIMIT="3/minute")
    victim = new_wallet()

    codes = [new_browser(f"198.51.100.{i}").step1(victim) for i in range(1, 5)]

    assert [r.status_code for r in codes] == [200, 200, 200, 429]
    assert codes[3].get_json() == {"success": False, "error": "Too many requests for this wallet"}
    assert upstream.count("message") == 3  # the 4th made no outbound call
    assert new_browser("198.51.100.99").step1(new_wallet()).status_code == 200  # other wallets unaffected
    assert login.user_sessions and not [s for s in login.user_sessions.values() if s.get("pending")]


def test_s6_client_over_its_own_limit_does_not_burn_the_global_budget(
        monkeypatch, upstream, browser, new_browser, new_wallet):
    tiny(monkeypatch, STEP1_PER_ADDRESS_LIMIT="2/minute", STEP1_PER_ADDRESS_GLOBAL_LIMIT="3/minute")
    victim = new_wallet()

    noisy = [browser.step1(victim).status_code for _ in range(6)]
    assert noisy == [200, 200, 429, 429, 429, 429]  # uses 2 of the 3 global hits, not 6

    assert new_browser("198.51.100.2").step1(victim).status_code == 200  # the 3rd global hit
    assert new_browser("198.51.100.3").step1(victim).status_code == 429  # global exhausted


def test_s6_limit_is_keyed_on_the_lowercased_address(upstream, browser, new_wallet):
    victim = new_wallet()
    spellings = [victim.address, victim.acct.address, "0x" + victim.address[2:].upper()]
    codes = [browser.call(step=1, address=spellings[i % 3]).status_code for i in range(6)]
    assert codes == [200] * 5 + [429]


def test_s6_one_ip_cannot_fire_unbounded_nonce_requests_at_one_wallet(upstream, browser, new_browser, new_wallet):
    victim = new_wallet()
    for _ in range(20):
        browser.step1(victim)  # replaces its own session each time
    for _ in range(20):
        new_browser(browser.ip).step1(victim)  # fresh cookie jars hit the session quota or the wallet limit
    assert upstream.count("message") == 5


@pytest.mark.parametrize("name", ["STEP1_PER_ADDRESS_LIMIT", "STEP1_PER_ADDRESS_GLOBAL_LIMIT"])
def test_s6_malformed_wallet_limit_fails_at_import(name):
    code = "import login; print('imported')"
    base = {"PATH": "", "COOKIE_SECURE": "0", "PYTHONDONTWRITEBYTECODE": "1"}

    def run(value):
        return subprocess.run([sys.executable, "-c", code], cwd=REPO, env={**base, name: value},
                              capture_output=True, text=True, timeout=30)

    assert run("7/minute").stdout.strip() == "imported"  # control: a valid value starts fine
    bad = run("not-a-rate")
    assert bad.returncode != 0 and "imported" not in bad.stdout
    assert "ValueError" in bad.stderr


# ==========================================================================
# S7: non-object JSON body
# ==========================================================================

@pytest.mark.parametrize("body", [[1], "x", 7, True], ids=["list", "string", "number", "bool"])
def test_s7_non_object_json_body_is_400(body, upstream, browser):
    r = browser.raw(json=body)
    assert r.status_code == 400
    assert r.get_json() == {"success": False, "error": "Invalid request body"}
    assert upstream.count() == 0


@pytest.mark.parametrize("kwargs", [
    pytest.param({"data": b"", "content_type": "application/json"}, id="empty"),
    pytest.param({"data": b"{not json", "content_type": "application/json"}, id="unparsable"),
    pytest.param({"data": b'{"step": 1}', "content_type": "text/plain"}, id="not-json-content-type"),
])
def test_s7_missing_or_unparsable_json_still_means_invalid_step(kwargs, upstream, browser):
    r = browser.raw(**kwargs)
    assert (r.status_code, r.get_json()) == (400, {"success": False, "error": "Invalid step"})


# ==========================================================================
# S8: hardening
# ==========================================================================

@pytest.mark.parametrize("gt", ["abc123==\n", "abc def", "abc'x", 'a"b', "a;b"],
                         ids=["trailing-newline", "space", "quote", "dquote", "semicolon"])
def test_s8_unsafe_gt_never_becomes_a_command(gt, upstream, browser, wallet):
    upstream.gt = gt
    msg3 = browser.sign_in_to_step3(wallet)
    j = browser.step4(wallet, msg3).get_json()
    assert "command" not in j and j["success"] is False


@pytest.mark.parametrize("claimed", [
    pytest.param("0x" + "ab" * 20, id="different-valid-address"),
    pytest.param("not-an-address", id="garbage"),
    pytest.param("0x" + "zz" * 20, id="bad-hex"),
    pytest.param(12345, id="non-string"),
])
def test_s8_upstream_address_that_is_not_ours_falls_back_to_request_address(
        claimed, upstream, browser, wallet):
    upstream.account_address = claimed
    j = browser.step1(wallet).get_json()
    assert j["login_address"] == wallet.address
    assert upstream.of("message")[0].data == {"address": wallet.address}


def test_s8_same_address_in_checksum_case_is_kept(upstream, browser, wallet):
    upstream.account_address = wallet.acct.address  # EIP-55 spelling of the same address
    assert browser.step1(wallet).get_json()["login_address"] == wallet.acct.address


@pytest.mark.parametrize("step", [2, 3, 4])
def test_s8_session_vanishing_mid_request_is_401_not_500(step, upstream, browser, wallet):
    upstream.game_cookies = {"g": "1"}
    upstream.webtogame_result = ({"code": 5, "message": "denied"}, {"w": "1"}, 400)
    browser.sign_in_to_step3(wallet)
    attempt = {
        2: lambda: browser.step2(wallet, browser.msg1),
        3: browser.step3,
        4: lambda: browser.step4(wallet, browser.msg3),
    }[step]
    # The session expires (or finishes in another request) while upstream is answering.
    upstream.hooks[{2: "signin-wallet", 3: "game-message", 4: "webtogame"}[step]] = \
        login.user_sessions.clear

    r = attempt()

    assert r.status_code == 401


def test_s8_session_removed_after_webtogame_returned_gt_is_401_without_command(
        upstream, browser, wallet):
    msg3 = browser.sign_in_to_step3(wallet)
    # webtogame answers with a good gt and no cookies, so step 4 goes straight
    # to the success branch; the session is gone (expired / finished elsewhere) by then.
    upstream.hooks["webtogame"] = login.user_sessions.clear

    r = browser.step4(wallet, msg3)

    assert r.status_code == 401
    assert r.get_json() == {"success": False, "error": "Session expired or missing"}
    assert upstream.count("webtogame") == 1  # the gt was issued; single use is intended
    assert "msul://" not in r.get_data(as_text=True)


@pytest.mark.parametrize("kind,expected", [
    ("ok", 200), ("bad-request", 400), ("no-session", 401), ("bad-origin", 403),
])
def test_s8_api_responses_carry_cache_control_no_store(
        kind, expected, upstream, browser, wallet, new_browser):
    r = {
        "ok": lambda: browser.step1(wallet),
        "bad-request": lambda: browser.call(step="nope"),
        "no-session": lambda: new_browser("198.51.100.77").step3(),
        "bad-origin": lambda: browser.raw(headers={"Origin": "https://evil.example"}, json={"step": 1}),
    }[kind]()
    assert r.status_code == expected
    assert "no-store" in r.headers.get("Cache-Control", "")


def test_s8_oversized_413_carries_cache_control_no_store(upstream, browser, wallet):
    r = browser.raw(json={"step": 1, "address": wallet.address, "pad": "A" * 20_000})
    assert r.status_code == 413
    assert "no-store" in r.headers.get("Cache-Control", "")


def test_s8_flask_limiters_own_429_carries_cache_control_no_store(upstream, browser):
    limit = int(login.RATE_LIMIT.split("/")[0])
    codes = [browser.call(step="x").status_code for _ in range(limit + 1)]  # cheap local 400s
    assert codes[:limit] == [400] * limit

    r = browser.call(step="x")

    assert r.status_code == 429
    assert "no-store" in r.headers.get("Cache-Control", "")
    assert upstream.count() == 0


# ==========================================================================
# S9: secrets must not reach logs (expected: no code change needed)
# ==========================================================================

def test_s9_codes_tokens_and_commands_never_reach_the_log(caplog, upstream, browser, wallet, jwt):
    caplog.set_level(logging.DEBUG)  # root logger at DEBUG: the most verbose case
    upstream.signin_mfa = upstream.launch_mfa = True
    manual = jwt(42)

    msg1 = browser.step1(wallet).get_json()["message"]
    browser.step2(wallet, msg1)                        # upstream asks for the code
    browser.step2(wallet, msg1, mfa_code="123456")
    msg3 = browser.step3().get_json()["message"]
    r4 = browser.step4(wallet, msg3, mfa_code="123456", msu_wat=manual)
    command = r4.get_json()["command"]

    logged = caplog.text + "\n".join(rec.getMessage() for rec in caplog.records)
    secrets = ["123456", manual, jwt(1), upstream.gt, command,
               msg1, msg3, wallet.sign(msg1), wallet.sign(msg3)]
    assert not [s for s in secrets if s in logged]


def test_s9_failed_outbound_call_logs_only_the_exception_type(caplog, monkeypatch):
    secret = "jwt.SECRET.value"

    def transport_error(*args, **kwargs):  # real libraries echo URLs in messages
        raise requests.ConnectionError(f"https://msu.io/x?jwt={secret}&otp=123456")

    monkeypatch.setattr(login.requests, "post", transport_error)
    caplog.set_level(logging.DEBUG)

    assert login.post_r("https://msu.io/x", {"mfaCode": "123456"}) == (None, None, None)

    assert "ConnectionError" in caplog.text
    assert secret not in caplog.text and "123456" not in caplog.text


def test_s9_no_logging_call_site_references_request_data():
    """Inventory of every logger/print call in login.py: their arguments must
    not mention request bodies, cookies, tokens or commands."""
    forbidden = {
        "data", "request", "mfa_code", "signature", "signature1", "signature2",
        "cookies", "user_cookies", "merged", "token", "auth_jwt", "jwt_candidates",
        "gt", "result", "command", "state", "body", "headers",
    }
    tree = ast.parse((REPO / "login.py").read_text())
    log_methods = {"debug", "info", "warning", "error", "exception", "critical", "log"}
    sites = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        is_log = (isinstance(f, ast.Attribute) and f.attr in log_methods
                  and isinstance(f.value, ast.Name) and f.value.id in {"logger", "logging"})
        if is_log or (isinstance(f, ast.Name) and f.id == "print"):
            mentioned = {n.id for a in node.args for n in ast.walk(a) if isinstance(n, ast.Name)}
            sites.append((node.lineno, mentioned & forbidden))
    assert sites, "expected to find logging call sites"
    assert [s for s in sites if s[1]] == []
