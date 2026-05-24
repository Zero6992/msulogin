# MSU Login Launcher

這個專案本身已經是一個 Flask 網頁工具，不需要改任何業務邏輯。  
要讓其他人從網路上直接打開這個頁面，最簡單的做法是：

1. 用 `waitress` 啟動這個 Flask app。
2. 用 `cloudflared` 把本機的 `51222` port 公開成一個 HTTPS 網址。
3. 把 Cloudflare 給你的公開網址分享給其他人。

這份 README 走的是「臨時對外分享」路線，優點是不用改程式、不用開防火牆 inbound port、不用自己架 VPS。

## 使用前提

- 你的電腦要保持開機。
- `waitress` 和 `cloudflared` 這兩個程序都要持續執行。
- 其他人可以直接開這個網頁，但每個使用者自己的電腦仍然要有：
  - 桌面瀏覽器
  - MetaMask
  - 可處理 `msul://` 協定的 MapleStory N Launcher

## 1. 安裝 Python 套件

### WSL / Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install flask requests waitress
```

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install flask requests waitress
```

## 2. 啟動網站

不要用 `python login.py` 對外公開，因為那會跑 Flask 的開發伺服器。  
對外使用時改用 `waitress`。

### WSL / Linux / macOS

```bash
source .venv/bin/activate
waitress-serve --host=0.0.0.0 --port=51222 login:app
```

### Windows PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
waitress-serve --host=0.0.0.0 --port=51222 login:app
```

看到類似下面訊息就代表網站已經起來了：

```text
Serving on http://0.0.0.0:51222
```

先在自己電腦測一次：

```text
http://127.0.0.1:51222
```

## 3. 安裝 cloudflared

### WSL / Ubuntu / Debian

```bash
sudo mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-public-v2.gpg | sudo tee /usr/share/keyrings/cloudflare-public-v2.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-public-v2.gpg] https://pkg.cloudflare.com/cloudflared any main" | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt-get update && sudo apt-get install cloudflared
cloudflared --version
```

### Windows PowerShell

```powershell
winget install --id Cloudflare.cloudflared
cloudflared --version
```

如果你是其他系統，直接照 Cloudflare 官方下載頁安裝對應版本即可。

## 4. 對外開一個公開網址

開第二個 terminal，進到專案目錄後執行：

### WSL / Linux / macOS

```bash
cloudflared tunnel --url http://127.0.0.1:51222
```

### Windows PowerShell

```powershell
cloudflared tunnel --url http://127.0.0.1:51222
```

成功後終端會印出一個公開網址，格式大概像這樣：

```text
https://random-name.trycloudflare.com
```

把這個網址貼給其他人，他們就可以直接打開網頁。

## 5. 你實際要做的事情

1. 開第一個 terminal，跑 `waitress-serve --host=0.0.0.0 --port=51222 login:app`
2. 開第二個 terminal，跑 `cloudflared tunnel --url http://127.0.0.1:51222`
3. 複製 `https://xxxxx.trycloudflare.com`
4. 用手機網路或另一台電腦打開該網址確認可以看到頁面
5. 分享這個網址給其他人

## 6. 關閉方式

- 關掉網站：在跑 `waitress` 的 terminal 按 `Ctrl+C`
- 關掉公開網址：在跑 `cloudflared` 的 terminal 按 `Ctrl+C`

只要其中一個程序停掉，外部就不能用了。

## 7. 常見問題

### 1. 別人打不開

先檢查：

1. `waitress` 還在跑
2. `cloudflared` 還在跑
3. 你分享的是 `https://xxxxx.trycloudflare.com`，不是 `127.0.0.1`

### 2. `cloudflared tunnel --url ...` 失敗

如果你本機有 `~/.cloudflared/config.yaml`，Quick Tunnel 可能不能用。先暫時改名後再試：

```bash
mv ~/.cloudflared/config.yaml ~/.cloudflared/config.yaml.bak
```

用完再改回去：

```bash
mv ~/.cloudflared/config.yaml.bak ~/.cloudflared/config.yaml
```

### 3. `51222` port 被占用

把 `waitress` 和 `cloudflared` 兩邊都改成同一個沒被占用的 port，例如 `18080`：

```bash
waitress-serve --host=0.0.0.0 --port=18080 login:app
cloudflared tunnel --url http://127.0.0.1:18080
```

### 4. 網頁打得開，但不能直接啟動遊戲

這是正常的。  
`msul://` 是使用者自己電腦上的本機協定，所以每個使用者自己的電腦都必須已經安裝對應的 launcher。

## 8. 重要限制

- `trycloudflare.com` 這種 Quick Tunnel 網址每次重開都會變。
- Quick Tunnel 比較適合測試或臨時分享，不適合正式長期營運。
- 這個工具會把流程中的 cookie / JWT 暫存在記憶體裡，所以不要把它當成無保護的公開服務長期暴露在外網。

如果你要固定網址、長期可用、重開機後自動恢復，下一步應該改用 Cloudflare Named Tunnel 或把這個專案部署到一台固定在線的主機。

## 參考文件

- Flask Deploy to Production: https://flask.palletsprojects.com/en/stable/tutorial/deploy/
- Waitress command line runner: https://docs.pylonsproject.org/projects/waitress/en/latest/runner.html
- Cloudflare Tunnel downloads: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/
- Cloudflare Quick Tunnels: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/
