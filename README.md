# 🔒 DevPaste

**End-to-end encrypted, zero-knowledge secret sharing** — built by <a href="https://devstudioal.com" target="_blank">DevStudioAl</a>.

Share passwords, API keys, tokens, or any sensitive data. Your content is encrypted in the browser before it ever leaves your device. The server never sees the plaintext — not even for a millisecond.

---

## How it works

1. You type a secret and click **Generate encrypted link**
2. Your browser generates a random AES-256-GCM key and encrypts the content locally
3. Only the **ciphertext** is sent to the server — the key stays in the `#fragment` of the URL
4. The recipient opens the link — their browser reads the key from the fragment and decrypts locally
5. The server never had the key. It cannot read your data.

> **Why the `#fragment` matters:** Browsers never send the `#` part of a URL to the server. It is a client-only construct defined by the HTTP spec. This is the core of the zero-knowledge guarantee.

---

## Features

- **AES-256-GCM encryption** via the browser's native Web Crypto API — no libraries
- **Zero-knowledge** — server stores only ciphertext + IV, never plaintext or the key
- **Configurable TTL** — 5 minutes, 1 hour, 1 day, 7 days, or 30 days
- **Burn after read** — message self-destructs after the first view
- **Password protection** — optional second layer, verified with bcrypt server-side
- **Security headers** — CSP, `Referrer-Policy: no-referrer`, `X-Frame-Options`, `Permissions-Policy`
- **Brute-force protection** — password unlock is rate-limited to 10 attempts per 10 minutes per IP
- **Payload size limits** — paste creation capped at 2 MB, password unlock capped at 1 KB
- **No external dependencies** — vanilla HTML/CSS/JS, no CDN, no tracking

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Go 1.21 — `net/http` standard library |
| Database | SQLite via `modernc.org/sqlite` (pure Go, no CGo) |
| Frontend | Vanilla HTML + CSS + JavaScript |
| Encryption | Browser Web Crypto API (`crypto.subtle`) |
| Password hashing | bcrypt via `golang.org/x/crypto` |

---

## Security headers (applied to every response)

| Header | Purpose |
|---|---|
| `Content-Security-Policy` | `connect-src 'self'` blocks data exfiltration even if JS were tampered with |
| `Referrer-Policy: no-referrer` | Prevents the `#key` fragment from leaking via the Referer header |
| `X-Frame-Options: DENY` | Clickjacking protection |
| `X-Content-Type-Options: nosniff` | Prevents MIME-type sniffing attacks |
| `Permissions-Policy` | Disables camera, microphone, geolocation, payment APIs |

---

## API

**Pages**

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Landing page |
| `GET` | `/new` | Create paste page |
| `GET` | `/v/:id` | View / decrypt paste page |
| `GET` | `/privacy` | Privacy Policy |
| `GET` | `/terms` | Terms of Service |

**API**

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/paste` | Create a new encrypted paste |
| `GET` | `/api/paste/:id` | Retrieve ciphertext + metadata |
| `POST` | `/api/paste/:id/unlock` | Unlock a password-protected paste |

### Create paste — request body

```json
{
  "encrypted_content": "<base64url ciphertext>",
  "iv": "<base64url IV>",
  "ttl": 3600,
  "burn_after_read": false,
  "password": ""
}
```

---

## Running locally

**Requirements:** Go 1.21+

```bash
git clone https://github.com/DevStudioAl/devpaste.git
cd devpaste
go build -o devpaste .
./devpaste
```

Server starts on port `5000` by default. Set the `PORT` environment variable to override.

```
http://localhost:5000
```

---

## Project structure

```
devpaste/
├── main.go           # HTTP server, API handlers, SQLite storage, security middleware
├── go.mod
├── go.sum
└── static/
    ├── home.html     # Landing page
    ├── new.html      # Create paste page
    ├── view.html     # View / decrypt paste page
    ├── privacy.html  # Privacy Policy (GDPR-compliant, zero-knowledge focused)
    ├── terms.html    # Terms of Service
    ├── style.css     # Shared stylesheet (view, privacy, terms pages)
    └── hero-bg.jpg   # Background image
```

---

## Honest limitations

Like all browser-based encrypted services (Bitwarden web vault, ProtonMail web client), DevPaste has one inherent constraint: the server delivers the JavaScript that runs in your browser. A compromised server could theoretically serve malicious JS.

Mitigations already in place:
- No external JS dependencies — nothing loaded from CDNs
- Strict `Content-Security-Policy` blocks exfiltration even if JS is tampered with
- `Referrer-Policy: no-referrer` protects the key in the URL fragment
- Open source — anyone can audit what code is actually being served

---

## License

MIT — see [LICENSE](LICENSE)

---

Built with care by <a href="https://devstudioal.com" target="_blank">DevStudioAl</a>
