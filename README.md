# MSU Login Launcher

開源、可自行架設的小工具：把 **MetaMask 的錢包簽名**橋接成 MapleStory N 的
`msul://` 啟動指令。連錢包 → 簽名 → 複製產生的指令貼到瀏覽器 → 進遊戲。

> ⚠️ 非官方工具，依賴 msu.io 的內部 API。MSU 改版時可能失效；請自行評估使用。

---

## 運作流程

1. 連接 MetaMask
2. 在 MetaMask 簽第一段訊息（登入挑戰）
3. 伺服器把簽名中繼給 msu.io，取得登入 session
4. 簽第二段訊息（遊戲挑戰）→ 換回遊戲 token（`gt`）
5. 產生 `msul://…` 指令，貼進瀏覽器網址列 → 啟動器開遊戲

若帳號在 MSU 的 **Account Security** 綁了 2FA（Google Authenticator），流程中會跳出
輸入框要求 6 位數驗證碼。MSU 有兩道各自獨立的關卡，兩道都開的話會分別要求一次：

- **Wallet Connect** — 擋在登入（`signin-wallet`）
- **MapleStory N Launch** — 擋在取得遊戲 token（`webtogame`）

## 使用前提

每個使用者自己的電腦要有：

- 桌面瀏覽器
- MetaMask 擴充功能
- 能處理 `msul://` 協定的 MapleStory N Launcher

---

## 安全性與信任

會擔心「在別人的網站授權錢包」很正常，這裡把實際狀況講清楚：

**它做不到的事（重要）**

- **只用 `personal_sign`（純訊息簽名），永遠不會要求交易或代幣授權。**
  這種簽名帶有 `\x19Ethereum Signed Message` 前綴，本質上不可能是一筆交易或
  `approve`，**沒辦法轉走、動用或授權你錢包裡的任何資產**。
- **從不接觸你的私鑰或助記詞。** 簽名全程在 MetaMask 內完成，本服務只拿到
  「簽名結果」這串 hex，你的金鑰永遠不會離開錢包。
- 簽名前，請在 MetaMask 視窗**看清楚要簽的訊息內容**（應該是 msu.io 的登入挑戰
  文字）。訊息內容是可讀的，覺得不對就別簽。

**誠實說的殘餘風險**

- 這個流程會把你的簽名在後端中繼給 msu.io，換回你的 **MSU 登入 / 遊戲 token**。
  所以連到**別人架設**的站台，等於信任該站台會經手你這一次的 MSU session —— 惡意
  站台在 token 有效期間內有機會存取你的 **MSU 帳號 / 遊戲**（但偷不到你的加密資產）。

**所以最安全的用法 = 自己在本機跑**

程式碼公開、可自行審閱，本機執行時簽名與 token 全程不離開你的電腦。想圖方便用別人
架的站也可以，就自行判斷是否信任對方。

**服務端的強化**（見 git history 的 `fix(security)` commits）

- Session 用 server 端隨機 ID + `HttpOnly; Secure; SameSite=Strict` cookie，不拿錢包地址當 key
- 每段簽名都用 `eth-account` 在本地驗證，確認確實出自該錢包
- `/api/launch` 有 per-IP rate limit、in-flight session 數上限、`Origin` 檢查
- 嚴格驗證 address、signature、`gt`、MFA 驗證碼的格式
- CSP、HSTS、`X-Frame-Options` 等安全 header（透過 `flask-talisman`）
- 例外不回傳 stack trace，只回一組 UUID
- **不持久化任何東西**：token 只暫存在記憶體（5 分鐘 TTL），隨程序重啟消失

---

## 自行架設 / 本地執行

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 本機是純 HTTP，要關掉 cookie 的 Secure flag，瀏覽器才會帶 session cookie
COOKIE_SECURE=0 python login.py
```

開 <http://127.0.0.1:51222> 使用。

要對外部署到任何平台，repo 附了 `Procfile`（用 `waitress` 起 WSGI），可直接沿用；
放在會終止 TLS 的反向代理後面時，記得搭配 `--trusted-proxy` 並視情況開 `FORCE_HTTPS`。
不過對一般使用者，**直接在本機跑是最單純也最安全的方式**。

## 環境變數

| 變數 | 預設 | 用途 |
| --- | --- | --- |
| `PORT` | `51222` | 監聽埠；部署平台通常會自動帶入 |
| `COOKIE_SECURE` | `1` | session cookie 的 Secure flag；本機純 HTTP 才設 `0` |
| `FORCE_HTTPS` | `0` | Talisman 是否強制 HTTPS。**只有在反向代理有送 `--trusted-proxy` 時才可開**，否則看不到 `X-Forwarded-Proto: https`，會被無限轉址 |
| `SESSION_TTL_SECONDS` | (寫死 300) | 目前是程式碼常數，要改請編輯 `login.py` |
| `MAX_SESSIONS` | `1000` | 同時 in-flight session 數上限 |
| `RATE_LIMIT` | `30/minute` | `/api/launch` per-IP 上限 |
| `ALLOWED_ORIGINS` | (空) | 額外允許的 Origin（逗號分隔）；同網域已自動允許 |
| `LOG_LEVEL` | `INFO` | logging 等級 |
| `RATELIMIT_STORAGE_URI` | `memory://` | flask-limiter 儲存後端；多 instance 才需改成 `redis://…` |

## 限制

- 非官方工具，靠 msu.io 內部 API 逆向而來，MSU 改版可能隨時失效
- `msul://` 是本機協定，每台電腦都要自己裝對應的 launcher
- 不存任何持久資料，所有 in-flight session 隨 process 重啟消失
- 預設單 instance；要 scale 得改 `RATELIMIT_STORAGE_URI` 並改用外部 session store

## 檔案結構

```
login.py             # Flask app + /api/launch 業務邏輯（含 2FA 流程）
templates/index.html # 前端頁面 + MetaMask 互動 + 2FA 輸入
requirements.txt     # 鎖版本的相依套件
Procfile             # 選用：用 waitress 對外部署時的啟動指令
.gitignore
```
