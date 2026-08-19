# MSU Login Launcher

MSU Login Launcher 是一個可自行部署的 Flask 應用程式，負責將 MetaMask 的錢包簽名流程轉換為 MapleStory N Launcher 可處理的 `msul://` 啟動指令。

使用者在瀏覽器完成兩次訊息簽名後，後端會與 msu.io 交換登入憑證及遊戲 token，最後產生可交給本機 Launcher 執行的啟動指令。流程同時支援 MSU Account Security 中的 `Wallet Connect` 與 `MapleStory N Launch` 兩道 2FA 驗證。

> [!WARNING]
> 本專案是非官方工具，並依賴 msu.io 的未公開 API。上游介面或驗證流程變更時，功能可能失效。請先閱讀下方的[安全性與信任模型](#安全性與信任模型)，並自行評估使用風險。

## 運作流程

1. 前端透過 MetaMask 取得使用者的錢包位址。
2. 後端向 msu.io 取得登入挑戰訊息，前端使用 `personal_sign` 完成第一次簽名。
3. 後端驗證簽章與錢包位址相符，再將簽章送往 msu.io 建立登入 session。
4. 後端取得遊戲挑戰訊息，前端完成第二次簽名。
5. 後端以第二次簽章交換遊戲 token（`gt`），並組成 `msul://` 啟動指令。
6. 使用者將指令貼入瀏覽器網址列，由本機 MapleStory N Launcher 啟動遊戲。

若帳號已啟用 Google Authenticator，介面會在對應階段要求輸入 2FA 驗證碼。MSU 將兩項設定視為獨立驗證關卡，因此兩者都啟用時會各驗證一次：

- `Wallet Connect`：建立 MSU 登入 session 前驗證。
- `MapleStory N Launch`：取得遊戲 token 前驗證。

## 使用需求

- Python 3
- 桌面版瀏覽器
- MetaMask 瀏覽器擴充功能
- 已註冊 `msul://` 協定的 MapleStory N Launcher

## 本機執行

建立虛擬環境並安裝相依套件：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

本機使用 HTTP 時，必須停用 session cookie 的 `Secure` 屬性：

```bash
COOKIE_SECURE=0 python login.py
```

服務啟動後，前往 <http://127.0.0.1:51222>，連接 MetaMask 並依畫面指示完成簽名。產生的 `msul://` 指令需貼到瀏覽器網址列執行。

## 部署

專案附有 `Procfile`，預設使用 Waitress 啟動單一處理程序，適合部署在由反向代理終止 TLS 的平台：

```text
web: waitress-serve --host=0.0.0.0 --port=${PORT:-51222} --threads=8 --trusted-proxy='*' --trusted-proxy-count=1 --trusted-proxy-headers='x-forwarded-for x-forwarded-proto' login:app
```

正式環境應使用 HTTPS，並保留 `COOKIE_SECURE=1`。如果反向代理的層數或轉送標頭與上述設定不同，請同步調整 `--trusted-proxy`、`--trusted-proxy-count` 與 `--trusted-proxy-headers`。只有在應用程式能正確判斷原始請求使用 HTTPS 時，才應啟用 `FORCE_HTTPS=1`。

## 環境變數

| 變數 | 預設值 | 說明 |
| --- | --- | --- |
| `PORT` | `51222` | `Procfile` 使用的監聽埠；直接執行 `login.py` 時固定為 `51222`。 |
| `COOKIE_SECURE` | `1` | 是否為 session cookie 設定 `Secure`；僅限本機 HTTP 開發時設為 `0`。 |
| `FORCE_HTTPS` | `0` | 是否由 Flask-Talisman 強制重新導向 HTTPS。啟用前需確認反向代理的轉送標頭設定正確。 |
| `MAX_SESSIONS` | `1000` | 記憶體內允許的作用中 session 數量上限。 |
| `RATE_LIMIT` | `30/minute` | `/api/launch` 對每個 IP 套用的請求頻率限制。 |
| `ALLOWED_ORIGINS` | 空值 | 額外允許的 Origin，以逗號分隔；同網域 Origin 會自動放行。 |
| `LOG_LEVEL` | `INFO` | Python logging 等級。 |
| `RATELIMIT_STORAGE_URI` | `memory://` | Flask-Limiter 的儲存後端；部署多個執行個體時應改用 Redis 等共用儲存。 |

應用程式 session 的逾時門檻目前固定為 300 秒，由 `login.py` 中的 `SESSION_TTL_SECONDS` 控制，並非環境變數。

## 安全性與信任模型

### 錢包操作範圍

前端只會透過 MetaMask 呼叫 `eth_requestAccounts` 與 `personal_sign`。`personal_sign` 產生的是 EIP-191 訊息簽章，不會送出鏈上交易，也不會建立 ERC-20 代幣授權。私鑰與助記詞始終由 MetaMask 保管，不會傳送至本應用程式。

訊息簽章仍具備身分驗證能力。簽名前應確認 MetaMask 顯示的內容確實是 msu.io 提供的登入或遊戲挑戰；內容不符時請取消操作。

### 遠端站台的信任邊界

後端必須接收簽章，並代為處理 MSU session cookie 與遊戲 token。使用第三方部署的站台，代表站台營運者在憑證有效期間內可能存取該次 MSU session 或遊戲帳號。這項風險與鏈上資產不同，但仍屬於帳號存取風險。

建議自行在本機執行；若使用遠端版本，請先確認程式碼與站台營運者都值得信任。產生的 `msul://` 指令包含可用於啟動遊戲的 token，不應分享或寫入公開紀錄。

### 已實作的防護

- 以伺服器產生的隨機 session ID 綁定錢包位址，預設使用 `HttpOnly; Secure; SameSite=Strict` cookie。
- 使用 `eth-account` 驗證兩次簽章，並比對伺服器端保留的原始挑戰訊息與錢包位址。
- 對 `/api/launch` 套用每個 IP 的請求頻率限制、作用中 session 數量上限與 Origin 檢查。
- 驗證錢包位址、簽章、遊戲 token 與 2FA 驗證碼格式。
- 透過 Flask-Talisman 設定 CSP、HSTS、`X-Frame-Options` 與 Referrer Policy。
- 未處理的例外只會向用戶端回傳追蹤 ID，完整錯誤堆疊僅保留於伺服器記錄。
- MSU cookies 與 token 僅暫存在處理程序的記憶體中；session 逾時、啟動成功或服務重新啟動時會從記憶體移除，不會寫入應用程式資料庫或檔案。

## 已知限制

- msu.io 的未公開 API 沒有相容性保證，任何上游改版都可能中斷登入流程。
- 僅支援 MetaMask；後端送往 MSU 的錢包類型固定為 `WALLET_TYPE_METAMASK`。
- `msul://` 是本機自訂協定，每台使用者裝置都必須安裝對應的 Launcher。
- session 與請求頻率限制的狀態預設儲存在單一處理程序的記憶體內。多處理程序或多執行個體部署需要共用的 session 儲存層，並為 Flask-Limiter 設定外部儲存後端。

## 專案結構

```text
login.py             # Flask 應用程式、MSU API 流程與 2FA 處理
templates/index.html # 使用者介面、MetaMask 互動與啟動指令輸出
requirements.txt     # Python 相依套件與版本
Procfile             # Waitress 部署啟動指令
.gitignore           # Git 忽略規則
```
