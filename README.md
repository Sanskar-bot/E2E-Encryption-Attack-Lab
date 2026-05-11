# MITM Attack & E2E Encryption Demo
**Sanskar Phougat · B.Tech ECE · JIIT Noida · CyberPeace Foundation Assignment**

---

## Project overview

A three-act live demonstration showing:

| Act | Description | What MITM sees |
|-----|-------------|----------------|
| **Act 1** | Unencrypted plaintext chat | Full plaintext |
| **Act 2** | RSA+AES-GCM encrypted chat (no key verification) | Full plaintext via key swap |
| **Act 3** | RSA+AES-GCM + fingerprint verification | Nothing — session aborts |

All traffic runs on `127.0.0.1` using five terminal windows simultaneously.

---

## File structure

```
E2E MITM/
├── crypto_utils.py       # Shared crypto helpers (RSA, AES-GCM, fingerprint)
├── server.py             # Dumb TCP relay — forwards bytes between clients
├── alice.py              # Alice client (plain / encrypted / verified)
├── bob.py                # Bob client  (plain / encrypted / verified)
├── mitm.py               # MITM TCP proxy + Flask attacker dashboard API
├── mitm_addon.py         # mitmproxy addon (professional tool, Act 2)
├── dashboard/
│   └── index.html        # Live attacker dashboard (open in browser)
├── screenshots/          # Save your evidence PNGs and .pcapng here
├── report/               # Your final PDF report goes here
└── README.md
```

---

## Dependencies

```bash
pip install cryptography flask flask-cors mitmproxy
```

---

## How to run each act

### Ports used
| Component | Port |
|-----------|------|
| MITM proxy | 8080 |
| Real server | 9000 |
| Dashboard API | 7000 |

---

### Act 1 — Plaintext + Burp Suite

Open **4 terminal windows**:

```bash
# Terminal 1
python server.py

# Terminal 2  (also configure Burp Suite to listen on :8080 → forward to :9000)
# (Burp Suite acts as the MITM for Act 1 — no mitm.py needed)

# Terminal 3
python alice.py plain

# Terminal 4
python bob.py plain
```

Then open Wireshark → Loopback interface → filter `tcp.port == 9000`.

---

### Act 2 — Encrypted chat + MITM key swap

Open **5 terminal windows**:

```bash
# Terminal 1
python server.py

# Terminal 2
python mitm.py          # starts proxy on :8080 AND Flask API on :7000

# Terminal 3
python alice.py encrypted

# Terminal 4
python bob.py encrypted

# Terminal 5 (browser)
# Open  dashboard/index.html  in your browser
# (Or open http://127.0.0.1:7000  — but you need to serve index.html from Flask)
# Simplest: just open dashboard/index.html directly as a file
```

Watch Terminal 2 (mitm.py) print `⚠ KEY SWAP` and then `🔓 DECRYPTED` for every message.

---

### Act 3 — Verified fingerprint check (with MITM → attack fails)

```bash
# Terminal 1
python server.py

# Terminal 2
python mitm.py

# Terminal 3
python alice.py verified

# Terminal 4
python bob.py verified
```

Both Alice and Bob will print mismatched fingerprints and prompt `[yes/no]`.  
Type **`no`** → both clients abort → MITM gets nothing.

---

### Act 3 — Verified (WITHOUT MITM → success)

```bash
# Terminal 1
python server.py

# Terminal 2
python alice.py verified --direct     # connects to :9000 directly

# Terminal 3
python bob.py verified --direct
```

Both Alice and Bob will see **identical** fingerprints.  
Type **`yes`** → session proceeds → secure chat works.

---

## mitmproxy addon (Act 2 professional tool demo)

```bash
mitmproxy -s mitm_addon.py --listen-port 8080 --mode reverse:http://127.0.0.1:9000
```

Then run `alice.py encrypted` and `bob.py encrypted` as above.  
mitmproxy's TUI will show every intercepted request.

---

## Evidence to collect (screenshots)

| ID | What | Filename |
|----|------|----------|
| A1 | Burp Suite intercept tab — plaintext | `act1_burp.png` |
| A2 | Wireshark — plaintext in ASCII pane | `act1_wireshark.png` |
| B1 | MITM terminal showing decrypted messages | `act2_mitm_decrypts.png` |
| B2 | mitmproxy TUI with intercepted requests | `act2_mitmproxy.png` |
| B3 | Live dashboard showing key swaps + decrypted feed | `act2_dashboard.png` |
| C1 | Alice terminal — fingerprint mismatch warning | `act3_mismatch.png` |
| C2 | Alice + Bob terminals — matching fingerprints | `act3_match.png` |
| W1 | Wireshark side-by-side: plaintext vs ciphertext | `wireshark_compare.png` |

---

## Ethical notice

> All tests are conducted on localhost (127.0.0.1) in a controlled single-machine
> environment. No real network traffic was intercepted. This project is for
> educational purposes only as part of a CyberPeace Foundation assignment.
