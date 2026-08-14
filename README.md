# MSU Login Launcher

把 MetaMask 簽名橋接到 MapleStory N 的登入流程，產生 `msul://` 啟動指令。
使用者開網頁 → 連 MetaMask → 簽兩次 → 複製產生的指令貼到瀏覽器 → 進遊戲。

## 使用者前提

每個使用者自己的電腦要有：

- 桌面瀏覽器
- MetaMask 擴充功能
- 可處理 `msul://` 協定的 MapleStory N Launcher

## 部署到 Railway

這是預期的對外部署方式。

### 1. 把 repo 連到 Railway

把這個 repo push 到 GitHub，然後在 Railway 建一個 service，選 *Deploy from GitHub repo*。
Railway 會自動讀 `Procfile` 和 `requirements.txt`，用 `waitress` 啟動。

`Procfile` 裡的 `--trusted-proxy` 系列參數是必要的：waitress 從 2.0 起預設會把所有
`X-Forwarded-*` header 丟掉(`clear_untrusted_proxy_headers=True`)，不設就等於
`ProxyFix` 空轉 —— rate limit 會拿到 Railway proxy 的 IP 而不是真實 client IP,
HSTS 也永遠發不出來。只信任 `x-forwarded-for` 和 `x-forwarded-proto`;
`x-forwarded-host` 刻意不信任,以免 `request.host` 被改掉而破壞 Origin 檢查。

### 2. 設定環境變數

在 service 的 **Variables** 分頁加：

| 變數 | 建議值 | 說明 |
| --- | --- | --- |
| `FORCE_HTTPS` | (不用設) | Railway edge 已經會把 HTTP 301 轉到 HTTPS,Talisman 這層是重複的 |
| `RATE_LIMIT` | `30/minute` | 每個 IP 在 `/api/launch` 的速率上限 |
| `MAX_SESSIONS` | `1000` | 同時 in-flight session 數上限 |
| `ALLOWED_ORIGINS` | (空) | 額外允許的 Origin(逗號分隔);同網域已自動允許 |
| `LOG_LEVEL` | `INFO` | 記錄等級 |
| `RATELIMIT_STORAGE_URI` | `memory://` | 多 instance scale-out 才需改成 `redis://...` |

不要在 production 設 `COOKIE_SECURE=0`(那是本地 HTTP 開發用的)。

### 3. 自訂網域(選用)

Railway 預設給一個 `*.up.railway.app` 網址,直接用即可。
要綁自己網域,在 *Settings → Domains* 加上去。

### 4. 確認

打開 Railway 給的網址 → 連 MetaMask → 產生指令 → 複製 `msul://...` 貼到瀏覽器啟動遊戲。

## 本地開發

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 本地是純 HTTP,必須關掉 cookie 的 Secure flag,瀏覽器才會帶 session cookie
COOKIE_SECURE=0 python login.py
```

開 <http://127.0.0.1:51222> 測試。

## 安全性

這個服務經過一輪 OWASP 安全強化(見 git history 的 `fix(security)` commits):

- Session 用 server 端產生的隨機 ID + `HttpOnly; Secure; SameSite=Strict` cookie,不再用錢包地址當 key
- 步驟 2 / 步驟 4 都會用 `eth-account` 在本地驗證 MetaMask 簽名
- `/api/launch` 有 per-IP rate limit、session 數上限、`Origin` 檢查
- 嚴格驗證 address、signature、`gt` 的格式
- CSP、HSTS、`X-Frame-Options` 等 HTTP 安全 headers(透過 `flask-talisman`)
- 異常不再把 stack trace 字串回給 client,只回 UUID

仍要注意:JWT 暫存在記憶體裡(5 分鐘 TTL),所以這個服務不適合長期儲存使用者授權狀態。

## 環境變數速查

| 變數 | 預設 | 用途 |
| --- | --- | --- |
| `PORT` | `51222` | Railway 會自動帶入 |
| `COOKIE_SECURE` | `1` | session cookie 的 Secure flag;本地 HTTP 才設 `0` |
| `FORCE_HTTPS` | `0` | Talisman 是否強制 HTTPS。Railway edge 已經在做,通常不用開。<br>**只有在 `Procfile` 有 `--trusted-proxy` 時才可以開**,否則 Talisman 永遠看不到 `X-Forwarded-Proto: https`,每個請求都會被轉址 → 無限迴圈 |
| `SESSION_TTL_SECONDS` | (寫死 300) | 目前是程式碼常數,要改編輯 `login.py` |
| `MAX_SESSIONS` | `1000` | session dict 容量上限 |
| `RATE_LIMIT` | `30/minute` | `/api/launch` per-IP 上限 |
| `ALLOWED_ORIGINS` | (空) | 額外允許的 cross-origin 來源 |
| `LOG_LEVEL` | `INFO` | logging 等級 |
| `RATELIMIT_STORAGE_URI` | `memory://` | flask-limiter 儲存後端 |

## 限制

- `msul://` 是使用者本機協定,所以每個使用者自己的電腦都必須裝對應 launcher
- 不存任何持久資料,所有 in-flight session 隨 process 重啟消失
- 預設單 instance;要 scale 必須改 `RATELIMIT_STORAGE_URI` 並改用外部 session store

## 檔案結構

```
login.py             # Flask app + /api/launch 業務邏輯
templates/index.html # 前端頁面 + MetaMask 互動
requirements.txt     # 鎖版本的相依套件
Procfile             # Railway 啟動指令(waitress)
.gitignore
```

## 參考

- Flask deploy to production: <https://flask.palletsprojects.com/en/stable/tutorial/deploy/>
- Waitress runner: <https://docs.pylonsproject.org/projects/waitress/en/latest/runner.html>
- Railway docs: <https://docs.railway.app/>
