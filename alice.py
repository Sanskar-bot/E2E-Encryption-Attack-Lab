"""
alice.py
Role: Alice client — simulates the sender in all three acts of the MITM demo.
Usage:
    python alice.py plain       # Act 1 — no encryption, route through MITM
    python alice.py encrypted   # Act 2 — RSA+AES-GCM, no fingerprint check
    python alice.py verified    # Act 3 — RSA+AES-GCM + fingerprint verification

Default target:
    plain / encrypted / verified → 127.0.0.1:8080  (goes through the MITM proxy)
    Pass --direct flag to connect straight to the server on port 9000 (no MITM).
"""

import sys
import os
import json
import socket
import threading
import base64
import time

from crypto_utils import (
    generate_rsa_keypair,
    serialize_public_key,
    deserialize_public_key,
    rsa_encrypt,
    aes_encrypt,
    aes_decrypt,
    key_fingerprint,
)

SENDER = "alice"
MITM_PORT   = 8080
SERVER_PORT = 9000
HOST        = "127.0.0.1"


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def send_json(sock: socket.socket, obj: dict) -> None:
    """Send a JSON object followed by a newline."""
    data = json.dumps(obj).encode() + b"\n"
    sock.sendall(data)


def recv_json(sock: socket.socket, buffer: list) -> dict | None:
    """
    Block until a complete newline-delimited JSON message is received.
    Uses a mutable list as a persistent buffer across calls.
    """
    while True:
        if b"\n" in buffer[0]:
            line, buffer[0] = buffer[0].split(b"\n", 1)
            return json.loads(line)
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buffer[0] += chunk


def print_banner(mode: str, port: int) -> None:
    print("=" * 54)
    print(f"  ALICE  |  mode={mode.upper()}  |  target={HOST}:{port}")
    print("=" * 54)


# ─────────────────────────────────────────────
# Receiving thread
# ─────────────────────────────────────────────

def recv_loop(sock: socket.socket, aes_key_ref: list, mode: str, buffer: list) -> None:
    """Background thread: receive and print incoming messages."""
    while True:
        msg = recv_json(sock, buffer)
        if msg is None:
            print("[Alice] Connection closed.")
            break
        mtype = msg.get("type")
        sender = msg.get("sender", "?")
        if sender == SENDER:
            continue   # ignore echoes of our own messages

        if mtype == "message":
            if mode == "plain":
                print(f"\n  [{sender}] {msg.get('text', '')}")
            else:
                try:
                    plaintext = aes_decrypt(
                        aes_key_ref[0],
                        msg["nonce"],
                        msg["ciphertext"],
                    )
                    print(f"\n  [{sender}] {plaintext}")
                except Exception as e:
                    print(f"\n  [{sender}] <decrypt error: {e}>")
        elif mtype == "key_exchange":
            pass   # handled in handshake
        else:
            pass   # session_key or unknown — ignore in recv thread


# ─────────────────────────────────────────────
# Modes
# ─────────────────────────────────────────────

def run_plain(sock: socket.socket) -> None:
    """Act 1 — send and receive plaintext JSON messages."""
    buf = [b""]
    t = threading.Thread(target=recv_loop, args=(sock, [None], "plain", buf), daemon=True)
    t.start()
    print("[Alice] Plain mode ready. Type messages and press Enter.")
    print("[Alice] (Ctrl-C or empty line to quit)\n")
    try:
        while True:
            text = input()
            if not text:
                break
            send_json(sock, {"type": "message", "sender": SENDER, "text": text})
    except (KeyboardInterrupt, EOFError):
        pass


def run_encrypted(sock: socket.socket, verify: bool = False) -> None:
    """Act 2 (and Act 3) — RSA key exchange + AES-GCM encrypted chat."""
    buf = [b""]

    # ── Step 1: generate RSA keypair ──────────────────────────
    priv_key, pub_key = generate_rsa_keypair()
    print(f"[Alice] Generated RSA-2048 key pair.")
    fp = key_fingerprint(pub_key)
    print(f"[Alice] My fingerprint: {fp}")

    # ── Step 2: send public key ───────────────────────────────
    send_json(sock, {
        "type": "key_exchange",
        "sender": SENDER,
        "public_key": serialize_public_key(pub_key).decode(),
    })
    print("[Alice] Sent public key to server.")

    # ── Step 3: wait for Bob's public key ────────────────────
    print("[Alice] Waiting for Bob's public key…")
    while True:
        msg = recv_json(sock, buf)
        if msg is None:
            print("[Alice] Server closed connection during handshake.")
            return
        if msg.get("type") == "key_exchange" and msg.get("sender") != SENDER:
            bob_pub_key = deserialize_public_key(msg["public_key"])
            break
    print("[Alice] Received Bob's public key.")

    # ── Step 4 (Act 3): fingerprint verification ──────────────
    if verify:
        received_fp = key_fingerprint(bob_pub_key)
        print()
        print("╔══════════════════════════════════════════╗")
        print("║          FINGERPRINT VERIFICATION        ║")
        print("╠══════════════════════════════════════════╣")
        print(f"║  My key  : {fp}  ║")
        print(f"║  Bob's   : {received_fp}  ║")
        print("╚══════════════════════════════════════════╝")
        print()
        answer = input("  Call Bob out-of-band. Does Bob see the same fingerprint? [yes/no]: ").strip().lower()
        if answer != "yes":
            print()
            print("  ⚠  MITM ATTACK DETECTED — fingerprints do not match.")
            print("  ✗  Aborting session. No messages were exchanged.")
            sock.close()
            return
        print("  ✓  Fingerprint verified. Session is secure.\n")

    # ── Step 5: generate AES session key and send to Bob ──────
    # In verify mode the user's input() above already acts as a natural gate,
    # ensuring Bob's fingerprint prompt is visible before we send the key.
    # In encrypted mode there is no such gate, so we add a brief pause to give
    # Bob time to finish processing Alice's key_exchange and render his prompt
    # before the session_key races down the pipe in the same TCP window.
    if not verify:
        time.sleep(1.5)

    aes_key = os.urandom(32)
    encrypted_aes = rsa_encrypt(bob_pub_key, aes_key)
    send_json(sock, {
        "type": "session_key",
        "sender": SENDER,
        "encrypted_key": base64.b64encode(encrypted_aes).decode(),
    })
    print("[Alice] Session key sent (RSA-encrypted). AES-GCM chat starting…\n")

    # ── Step 6: start recv thread and chat loop ───────────────
    aes_key_ref = [aes_key]
    t = threading.Thread(target=recv_loop, args=(sock, aes_key_ref, "encrypted", buf), daemon=True)
    t.start()

    try:
        while True:
            text = input()
            if not text:
                break
            payload = aes_encrypt(aes_key, text)
            payload["type"] = "message"
            payload["sender"] = SENDER
            send_json(sock, payload)
    except (KeyboardInterrupt, EOFError):
        pass


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

def main() -> None:
    args = sys.argv[1:]
    mode = "plain"
    direct = False

    for a in args:
        if a in ("plain", "encrypted", "verified"):
            mode = a
        if a == "--direct":
            direct = True

    port = SERVER_PORT if direct else MITM_PORT
    print_banner(mode, port)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.connect((HOST, port))
        except ConnectionRefusedError:
            print(f"[Alice] Cannot connect to {HOST}:{port} — is the server/MITM running?")
            sys.exit(1)

        print(f"[Alice] Connected to {HOST}:{port}\n")

        if mode == "plain":
            run_plain(sock)
        elif mode == "encrypted":
            run_encrypted(sock, verify=False)
        elif mode == "verified":
            run_encrypted(sock, verify=True)

    print("[Alice] Session ended.")


if __name__ == "__main__":
    main()
