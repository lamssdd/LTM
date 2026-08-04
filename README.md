# 🛡️ Sentinel v3 — Multi-Agent Reconnaissance Scanner

> Hệ thống **trinh sát bảo mật (reconnaissance) đa tác tử** cho web/host, viết bằng Python.
> Kết hợp **Passive Recon → Active Recon → Aggregation** thành một pipeline duy nhất,
> có dashboard terminal thời gian thực và chế độ chạy qua console.

```
   ____            __  _            __   _____
  / __/__ ___  / /_(_)__  ___ / /  |_  /
 _\ \/ -_) _ \/ __/ / _ \/ -_) /  / __/
/___/\__/_//_/\__/_/_//_/\__/_/  /____/   v3.0
        Enterprise Pentest Multi-Agent System
```

> ⚠️ **Chỉ dùng cho mục đích hợp pháp.** Chỉ quét những mục tiêu mà bạn **được phép** kiểm thử
> (hệ thống của bạn, lab, hoặc target có văn bản uỷ quyền). Người dùng chịu trách nhiệm về việc sử dụng.

---

## 📖 Tổng quan

Sentinel v3 thực hiện **Phase 1 — Reconnaissance** của một quy trình pentest, được chia thành 3 agent nối tiếp:

| Phase | Agent | Nhiệm vụ |
|-------|-------|----------|
| **1a — Passive** | `PassiveReconAgent` | IP resolution, WHOIS, DNS records (A/AAAA/CNAME/MX/NS/TXT), subdomain enum nhẹ, SSL/TLS, technology fingerprinting. **Không gửi payload.** |
| **1b — Active**  | `ActiveReconAgent`  | HTTP availability, response headers & cookie flags, HTTP methods, port scan, robots.txt/sitemap, crawl (URLs/forms/params/JS endpoints), hidden endpoint discovery. |
| **1c — Aggregate** | `ReconAggregatorAgent` | Tổng hợp dữ liệu passive + active thành **JSON canonical** chuẩn, tính `summary`, lưu artifact. |

Kết quả cuối cùng được ghi ra `data/phase1_canonical.json` và lưu vào lịch sử scan (`data/scan_history.json`).

---

## ✨ Tính năng

- **Kiến trúc đa tác tử** với bộ nhớ dùng chung (`ScanMemory`) và điều phối qua `ScanOrchestrator`.
- **2 giao diện chạy:**
  - `main.py` — Dashboard terminal (thư viện [`rich`](https://github.com/Textualize/rich)) với log realtime, progress bar, theme "cybersecurity blue".
  - `phase1_console.py` — Chế độ console gọn nhẹ, phù hợp CI / script / xuất JSON.
- **`ToolTracker`** theo dõi trạng thái từng công cụ (pending / running / done / error) theo thời gian thực (hỗ trợ SSE).
- **3 chế độ thực thi công cụ** (`--mode`):
  - `auto` — tự chọn công cụ tốt nhất có sẵn (mặc định).
  - `local` — chỉ dùng công cụ cài trên máy hiện tại.
  - `kali_ssh` — chạy các công cụ nặng (nmap, httpx, naabu, katana, dnsx…) từ xa trên **máy Kali Linux qua SSH**.
- **Tích hợp bộ công cụ ProjectDiscovery** (tuỳ chọn): `httpx`, `dnsx`, `naabu`, `katana`.
- **Fallback thông minh:** thiếu `nmap` → socket scan; thiếu `ffuf` → HTTP probe; thiếu công cụ ngoài → parser thuần Python.
- **Lịch sử scan bền vững** để so sánh giữa các lần quét.

---

## 🗂️ Cấu trúc dự án

```
LTM/
├── main.py                     # Dashboard terminal (rich) — entrypoint chính
├── phase1_console.py           # Chế độ console / xuất JSON
├── orchestrator.py             # ScanOrchestrator + ToolTracker (điều phối pipeline)
├── memory.py                   # ScanMemory — bộ nhớ dùng chung giữa các agent
├── scan_history.py             # Lưu / đọc lịch sử scan bền vững
├── utils.py                    # Tiện ích chung (session, config, normalize URL...)
├── requirements.txt
│
├── agents/
│   ├── base_agent.py           # Lớp cơ sở cho mọi agent
│   ├── passive_recon_agent.py  # Phase 1a
│   ├── active_recon_agent.py   # Phase 1b
│   └── recon_aggregator_agent.py # Phase 1c
│
├── tools/                      # Wrapper cho công cụ ngoài
│   ├── kali_ssh_client.py      # Chạy công cụ từ xa qua SSH (paramiko)
│   ├── projectdiscovery_tools.py # Interface hợp nhất cho httpx/dnsx/naabu/katana
│   ├── httpx_runner.py
│   ├── dnsx_runner.py
│   ├── naabu_runner.py
│   └── katana_runner.py
│
└── data/                       # Artifact đầu ra
    ├── phase1_canonical.json   # Kết quả recon chuẩn hoá
    └── scan_history.json       # Lịch sử các lần scan
```

---

## 🚀 Cài đặt

### 1. Yêu cầu
- **Python 3.10+** (khuyến nghị 3.12)
- (Tuỳ chọn) [Nmap](https://nmap.org/) để port scan nhanh & chính xác hơn
- (Tuỳ chọn) Máy **Kali Linux** để dùng chế độ `kali_ssh`

### 2. Cài đặt

```bash
git clone https://github.com/lamssdd/LTM.git
cd LTM

python -m venv venv
# Windows
venv\Scripts\activate
# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt

# Hai gói sau được dùng nhưng chưa liệt kê trong requirements.txt — cài thêm:
pip install rich          # cần cho main.py (dashboard)
pip install paramiko      # cần nếu dùng chế độ kali_ssh
```

> 💡 **Cài Nmap (tuỳ chọn):**
> - Windows: `winget install -e --id Insecure.Nmap`
> - Linux: `sudo apt install nmap`
> Nếu không có, `ActiveReconAgent` tự fallback sang socket scanning.

---

## ⚙️ Cấu hình (`.env`)

Tạo file `.env` ở thư mục gốc (các biến shell luôn được ưu tiên hơn `.env`):

```ini
# Chế độ công cụ: auto | local | kali_ssh
PHASE1_TOOL_MODE=auto

# --- Chỉ cần khi dùng mode kali_ssh ---
KALI_HOST=192.168.1.50
KALI_PORT=22
KALI_USER=kali
KALI_PASS=your_password          # nên dùng key thay vì password
KALI_KEY_PATH=/path/to/id_rsa    # ưu tiên xác thực bằng khoá
KALI_CONNECT_TIMEOUT=10
```

---

## 💻 Sử dụng

### Dashboard terminal (`main.py`)

```bash
python main.py                              # Chế độ tương tác (hỏi target)
python main.py --target http://testfire.net # Quét trực tiếp một mục tiêu
python main.py --demo                        # Demo mode (mô phỏng, không quét thật)
python main.py --target example.com --mode local
```

| Cờ | Mô tả |
|----|-------|
| `-t, --target` | URL / hostname mục tiêu |
| `-d, --demo`   | Chạy mô phỏng bằng dữ liệu giả (an toàn để thử UI) |
| `-m, --mode`   | `auto` \| `local` \| `kali_ssh` (mặc định `auto`) |

### Chế độ console (`phase1_console.py`)

```bash
python phase1_console.py --target http://testfire.net
python phase1_console.py --target example.com --mode kali_ssh --output-json results.json
python phase1_console.py --target 192.168.1.1 --mode local --timeout 300
```

| Cờ | Mô tả | Mặc định |
|----|-------|----------|
| `--target` | URL / hostname (bắt buộc) | — |
| `--mode`   | `auto` \| `local` \| `kali_ssh` | `auto` |
| `--timeout`| Tổng thời gian scan tối đa (giây) | `600` |
| `--output-json` | Đường dẫn lưu kết quả JSON | (không lưu) |

---

## 📤 Kết quả đầu ra

Sau khi hoàn tất, dữ liệu được chuẩn hoá thành `data/phase1_canonical.json`:

```jsonc
{
  "target":    "https://example.com",
  "timestamp": "2026-04-03T18:38:21",
  "passive_recon": { "domain": "...", "ip_addresses": [...], "whois": {...},
                     "dns_records": {...}, "ssl": {...}, "technology": [...] },
  "active_recon":  { "availability": {...}, "headers": {...}, "http_methods": [...],
                     "ports": [...], "crawl": {...}, "hidden_endpoints": [...] },
  "summary":       { "total_urls": 0, "total_forms": 0, "total_params": 0,
                     "total_notable_endpoints": 0, "total_hidden_endpoints": 0,
                     "ssl_valid": true, "nmap_used": false, "ffuf_used": false,
                     "limitations": [] }
}
```

Mỗi lần quét cũng được ghi vào `data/scan_history.json` để xem lại / so sánh.

---

## 🧰 Công nghệ sử dụng

- **Ngôn ngữ:** Python 3
- **UI terminal:** `rich`
- **HTTP & parsing:** `requests`, `beautifulsoup4`, `lxml`
- **Network / OSINT:** `dnspython`, `python-whois`, `python-nmap`
- **SSH từ xa (Kali):** `paramiko`
- **Công cụ ngoài (tuỳ chọn):** Nmap, ProjectDiscovery (`httpx`, `dnsx`, `naabu`, `katana`), `ffuf`

> 📝 `requirements.txt` còn khai báo một số phụ thuộc nặng (`flask`, `crewai`, `litellm`,
> `langchain-openai`, `anthropic`, `python-owasp-zap-v2.4`, `weasyprint`) phục vụ các
> phase/tính năng mở rộng. Với luồng Phase 1 hiện tại, bạn có thể lược bớt nếu không cần.

---

## ⚠️ Lưu ý

1. **Uỷ quyền:** chỉ quét mục tiêu bạn sở hữu hoặc được phép kiểm thử. Active recon gửi request thật đến mục tiêu.
2. Một số công cụ (`nmap`, `httpx`, `naabu`, `katana`, `ffuf`) là **tuỳ chọn** — thiếu sẽ có fallback nhưng độ chính xác/tốc độ giảm.
3. `rich` và `paramiko` **chưa** có trong `requirements.txt` — nhớ cài thủ công (xem phần Cài đặt).
4. Không commit `.env` chứa thông tin đăng nhập Kali lên Git.

---

## 📄 License

Chưa chỉ định. Nếu bạn muốn mở nguồn, hãy thêm file `LICENSE` (ví dụ MIT).
