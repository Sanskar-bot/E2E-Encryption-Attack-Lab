# E2E Encryption Attack Lab

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Purpose](https://img.shields.io/badge/Purpose-Educational-orange)
![Platform](https://img.shields.io/badge/Platform-localhost%20only-lightgrey)

**Sanskar Phougat · B.Tech ECE · JIIT Noida · CyberPeace Foundation Assignment**

A hands-on, three-act simulation proving that **encryption by itself is insufficient** — and demonstrating how fingerprint-based key verification shuts down a Man-in-the-Middle attack.

---

## How It Works

![Architecture diagram — three acts of the MITM demo](assets/architecture.png)

| Act | Mode | What the MITM Sees |
|-----|------|--------------------|
| **Act 1** | Unencrypted chat | Every message in plain sight |
| **Act 2** | RSA + AES-GCM encryption (no key verification) | Full plaintext via an RSA key swap |
| **Act 3** | RSA + AES-GCM with fingerprint verification | Nothing — the session is terminated |

---

## Requirements

| Tool | Version | Download |
|------|---------|----------|
| Python | 3.10 + | [python.org](https://python.org) |
| Burp Suite Community | any | [portswigger.net](https://portswigger.net/burp) |
| Wireshark | any | [wireshark.org](https://wireshark.org) |

---

## Setup

```bash
# 1. Clone the repository
git clone https://github.com/Sanskar-bot/E2E-Encryption-Attack-Lab.git
cd E2E-Encryption-Attack-Lab

# 2. Install the required Python packages
pip install cryptography flask flask-cors mitmproxy
```

---

## Port Reference

| Component | Port | Launched by |
|-----------|------|-------------|
| Relay server | **9000** | `server.py` |
| MITM proxy | **8080** | `mitm.py` |
| Attacker dashboard API | **7000** | `mitm.py` (Flask, starts automatically) |

---

## Project Layout

```
E2E-Encryption-Attack-Lab/
├── crypto_utils.py          # RSA-2048, AES-256-GCM, SHA-256 fingerprint helpers
├── server.py                # Passive TCP relay — never inspects message content
├── alice.py                 # Alice client (plain / encrypted / verified modes)
├── bob.py                   # Bob client  (plain / encrypted / verified modes)
├── mitm.py                  # Active MITM proxy + Flask dashboard backend
├── mitm_addon.py            # mitmproxy professional-tool addon script
├── dashboard/
│   └── index.html           # Real-time attacker dashboard (open in any browser)
├── assets/                  # Images used in this README
└── README.md
```

---

## Act 1 — Intercepting Plaintext Traffic (Burp Suite)

### Configuring Burp Suite

**Step 1 — Proxy listener**  
Navigate to **Settings → Tools → Proxy → Proxy listeners** and verify the listener is bound to `127.0.0.1:8080`.

![Burp Suite proxy listeners panel](assets/act1_burp_listeners.png)

**Step 2 — Upstream proxy rule**  
Go to **Settings → Network → Upstream proxy servers → Add rule** and fill in:

| Field | Value |
|-------|-------|
| Destination host | `127.0.0.1` |
| Proxy host | *(leave blank)* |
| Proxy port | `9000` |

![Burp Suite upstream proxy rule dialog](assets/act1_burp_upstream.png)

**Step 3 — Turn on Intercept**  
Switch to the **Proxy → Intercept** tab and press **Intercept is on**.

![Burp Suite intercept tab](assets/act1_burp_intercept.png)

### Running Act 1 (4 terminals)

```bash
# Terminal 1 — start the relay server
python server.py

# Terminal 2 — Burp Suite acts as the MITM; mitm.py is not needed here

# Terminal 3
python alice.py plain

# Terminal 4
python bob.py plain
```

Launch **Wireshark**, select the **Loopback adapter**, and apply the filter `tcp.port == 9000` to watch raw plaintext packets flow by.

---

## Act 2 — Encrypted Chat with Active Key Swap

The MITM quietly substitutes its own RSA public keys for those of Alice and Bob, decrypts the AES session key, and reads every "encrypted" message without detection.

### Running Act 2 (5 terminals)

```bash
# Terminal 1
python server.py

# Terminal 2
python mitm.py          # starts proxy on :8080 and dashboard API on :7000

# Terminal 3
python alice.py encrypted

# Terminal 4
python bob.py encrypted

# Terminal 5 — launch the dashboard
# Simply open  dashboard/index.html  in your browser
```

**Expected output in Terminal 2:**

```
⚠  KEY SWAP  | bob   | Swapped bob's RSA public key with MITM's key
⚠  KEY SWAP  | alice | Swapped alice's RSA public key with MITM's key
🔑 SESSION KEY | alice | Decrypted AES session key: 3d9c6a7a…
🔑 SESSION KEY | alice | Re-encrypted AES key with Bob's real public key ✓
🔓 DECRYPTED | alice | hey
🔓 DECRYPTED | bob   | hello
```

Alice and Bob think their conversation is private — the MITM is reading every word.

---

## Act 3 — Fingerprint Verification (Attack Is Blocked)

### With the MITM active (attack detected → session aborted)

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

Each party displays the fingerprint of the key they received.  
Because the MITM swapped the keys, **the fingerprints will not match**.  
Enter **`no`** on both clients → both sessions abort → the MITM captures nothing.

```
⚠  MITM ATTACK DETECTED — fingerprints do not match.
✗  Aborting session. No messages were exchanged.
```

---

### Without the MITM (genuine end-to-end encryption)

```bash
# Terminal 1
python server.py

# Terminal 2  (mitm.py is not started)
python alice.py verified --direct     # connects directly to :9000

# Terminal 3
python bob.py verified --direct
```

Both parties see **identical** fingerprints.  
Enter **`yes`** → the session continues → fully encrypted chat with no eavesdropper present.

---

## Using mitmproxy as a Professional Tool (Act 2 Alternative)

```bash
mitmproxy -s mitm_addon.py --listen-port 8080 --mode reverse:http://127.0.0.1:9000
```

Then start `alice.py encrypted` and `bob.py encrypted`.  
mitmproxy's terminal UI will display every intercepted JSON frame in real time.

---

## Security Concepts Covered

| Concept | Demonstrated In |
|---------|----------------|
| Plaintext traffic sniffing | Act 1 — Wireshark / Burp Suite |
| RSA key swap attack | Act 2 — `mitm.py` |
| AES-GCM session key interception | Act 2 — `mitm.py` |
| Key fingerprint / safety-number verification | Act 3 — `alice.py verified` |
| Signal / WhatsApp-style safety numbers | Act 3 — SHA-256 of DER-encoded public key |

---

## Evidence Capture Checklist

| ID | Screenshot | Expected Filename |
|----|-----------|-------------------|
| A1 | Burp Suite intercept — plaintext messages visible | `act1_burp_intercept.png` |
| A2 | Wireshark — plaintext readable in the ASCII pane | `act1_wireshark.png` |
| B1 | MITM terminal — `🔓 DECRYPTED` log entries | `act2_mitm_decrypts.png` |
| B2 | mitmproxy TUI — intercepted JSON frames | `act2_mitmproxy.png` |
| B3 | Attacker dashboard — key swaps and decrypted message feed | `act2_dashboard.png` |
| C1 | Alice + Bob terminals — fingerprint mismatch warning | `act3_mismatch.png` |
| C2 | Alice + Bob terminals — matching fingerprints confirmed | `act3_match.png` |

---

## Ethical Disclaimer

> ⚠️ **All tests run exclusively on `127.0.0.1` (localhost) within a self-contained,
> single-machine environment. No real-world network traffic was intercepted or tampered with.
> This project is strictly educational and was created as part of a
> CyberPeace Foundation assignment. Do not apply these techniques to any
> network or system without explicit written permission from its owner.**

---

## License

MIT © 2026 Sanskar Phougat — see [LICENSE](LICENSE).
