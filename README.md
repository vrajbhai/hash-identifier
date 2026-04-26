Here's a complete `README.md` file for your VRAJBHAI Hash Identifier project:


# 🔍 VRAJBHAI — Hash Identifier

A professional hash identification tool supporting **150+ algorithms** with a cyberpunk-themed web interface. Built on the legendary `hash-identifier.py` by Zion3R/Blackploit, modernized with a Flask backend and real-time analysis.

![Version](https://img.shields.io/badge/version-2.2.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![Flask](https://img.shields.io/badge/flask-2.3.3-red)
![License](https://img.shields.io/badge/license-MIT-purple)

---

## ✨ Features

- 🔐 **150+ Hash Algorithms** — MD5, SHA-1, SHA-256, bcrypt, NTLM, Argon2, scrypt, and many more
- ⚡ **Instant Quick-Check** — Pattern-based detection without running the script
- 🧠 **Intelligent Caching** — 5-minute cache with auto-cleanup to avoid redundant processing
- 📊 **Bulk Analysis** — Identify up to 20 hashes simultaneously
- 🎨 **Cyberpunk UI** — Dark theme with scanlines, live timers, and loading animations
- 📱 **Responsive Design** — Works on desktop, tablet, and mobile
- 📋 **Session History** — Tracks your last 12 analyzed hashes
- 🔗 **Hashcat Mode Mapping** — Shows corresponding `hashcat -m` mode numbers
- ⏱️ **Configurable Timeout** — Adjust or disable via environment variables

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/vrajbhai/hash-identifier.git
   cd hash-identifier
   

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the backend**
   ```bash
   python app.py
   ```
   Your API will start at `http://127.0.0.1:5000`

4. **Open the frontend**
   - Open `index.html` in your browser
   - Or serve it with Python: `python -m http.server 8000`

---

## 🐳 Docker Deployment

```bash
# Build the image
docker build -t hash-identifier .

# Run the container
docker run -p 5000:5000 -e SCRIPT_TIMEOUT=120 hash-identifier
```

---

## ☁️ Deploy to Render (Free)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)

1. Fork this repository
2. Go to [Render.com](https://render.com) → New Web Service
3. Connect your forked repo
4. Set environment variables:
   - `SECRET_KEY` = `any-random-string`
   - `PYTHONUNBUFFERED` = `1`
   - `SCRIPT_TIMEOUT` = `300` (optional)
5. Click "Create Web Service"
6. Use [UptimeRobot](https://uptimerobot.com) to prevent sleep (ping `/health` every 5 min)

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/identify-hash` | Identify a single hash |
| `POST` | `/bulk-identify` | Identify up to 20 hashes |
| `POST` | `/quick-check` | Instant pattern check (no subprocess) |
| `GET` | `/health` | Health check with cache stats |
| `GET` | `/config` | Server configuration details |
| `POST` | `/cache/clear` | Clear result cache (requires admin secret) |

### Example Request

```bash
curl -X POST http://127.0.0.1:5000/identify-hash \
  -H "Content-Type: application/json" \
  -d '{"hash": "5d41402abc4b2a76b9719d911017c592"}'
```

### Example Response

```json
{
  "hash": "5d41402abc4b2a76b9719d911017c592",
  "possible_types": ["MD5", "MD4", "NTLM", "Domain Cached Credentials"],
  "least_possible": ["MySQL < 4.1"],
  "timed_out": false,
  "elapsed_ms": 245,
  "raw_output": "..."
}
```

---

## ⚙️ Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `SCRIPT_TIMEOUT` | `120` | Max seconds for hash analysis (0 = no timeout) |
| `CACHE_TTL` | `300` | Cache duration in seconds |
| `PORT` | `5000` | Server port |
| `ALLOWED_ORIGINS` | `*` | CORS allowed origins (comma-separated) |
| `ADMIN_SECRET` | `""` | Secret for cache clear endpoint |
| `SECRET_KEY` | required | Flask secret key (any random string) |
| `PYTHONUNBUFFERED` | `1` | Ensures real-time logging |

---

## 📁 Project Structure

```
hash-identifier/
├── app.py                  # Flask backend server
├── hash-identifier.py      # Core hash identification engine
├── index.html              # Frontend web interface
├── requirements.txt        # Python dependencies
├── Dockerfile              # Docker configuration
├── .dockerignore           # Docker build exclusions
├── snapdeploy.yaml         # SnapDeploy configuration
├── render.yaml             # Render configuration
└── README.md               # This file
```

---

## 🎯 Supported Hash Types

- **MD Family**: MD2, MD4, MD5, MD5(Unix), MD5(APR), MD5(WordPress), MD5(phpBB3)
- **SHA Family**: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 (including HMAC variants)
- **Unix Crypt**: DES(Unix), MD5(Unix), SHA-256(Unix), SHA-512(Unix)
- **Modern**: bcrypt, scrypt, Argon2, yescrypt
- **Framework**: Django (SHA-1, SHA-256, PBKDF2), Joomla, WordPress/phpBB3
- **Database**: MySQL, MySQL5
- **Windows**: NTLM, LM, Domain Cached Credentials
- **Others**: Whirlpool, RipeMD, Haval, Tiger, GOST, SNEFRU, and many more!

---

## 🔧 Troubleshooting

### "Cannot reach backend"
- Make sure `app.py` is running: `python app.py`
- Check the backend URL in `index.html` matches (default: `http://127.0.0.1:5000`)

### "Script timed out"
- Increase `SCRIPT_TIMEOUT` environment variable
- Set to `0` to disable timeout entirely

### "Hash contains invalid characters"
- Your hash has special characters not in the allowed set
- Check for hidden spaces or newlines

### Frontend shows no results
- Open browser console (F12) to see error details
- Verify the backend health: `curl http://127.0.0.1:5000/health`

---

## 🤝 Credits

- **Original Tool**: `hash-identifier.py` by [Zion3R](https://github.com/blackploit/hash-identifier)
- **Web Interface**: VRAJBHAI
- **Backend**: Flask + Python

---

## 📜 License

This project is for **educational purposes only**. The original hash-identifier.py is by Zion3R/Blackploit. Always use responsibly and only on hashes you own or have permission to analyze.

---

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=vrajbhai/hash-identifier&type=Date)](https://star-history.com/vrajbhai/hash-identifier&Date)

---

## 💬 Support

- **Issues**: [GitHub Issues](https://github.com/vrajbhai/hash-identifier/issues)
- **Discussions**: [GitHub Discussions](https://github.com/vrajbhai/hash-identifier/discussions)

---

Made with ❤️ by VRAJBHAI | Powered by Zion3R's hash-identifier
```

Just replace `vrajbhai` with your actual GitHub username, and you're all set! This README covers everything — installation, deployment, API docs, troubleshooting, and credits. 🚀
