"""
crypto_utils.py
Role: Shared cryptographic utility module for the MITM & E2E Encryption demo.
Usage: imported by alice.py, bob.py, mitm.py — never run directly.

Provides:
  - RSA-2048 key generation, serialization, encryption, decryption (OAEP+SHA-256)
  - AES-256-GCM symmetric encryption / decryption
  - SHA-256 key fingerprint formatter (the "safety number" Alice & Bob compare)
"""

import os
import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ─────────────────────────────────────────────
# RSA SECTION
# ─────────────────────────────────────────────

def generate_rsa_keypair():
    """Generate a 2048-bit RSA key pair. Returns (private_key, public_key)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()


def serialize_public_key(public_key):
    """Serialize an RSA public key to PEM-encoded bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem_bytes):
    """Deserialize PEM bytes back to an RSA public key object."""
    if isinstance(pem_bytes, str):
        pem_bytes = pem_bytes.encode()
    return serialization.load_pem_public_key(pem_bytes)


def rsa_encrypt(public_key, plaintext_bytes):
    """
    RSA-encrypt plaintext_bytes using OAEP + SHA-256 padding.
    Returns raw ciphertext bytes.
    """
    return public_key.encrypt(
        plaintext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, ciphertext_bytes):
    """
    RSA-decrypt ciphertext_bytes with OAEP + SHA-256 padding.
    Returns original plaintext bytes.
    """
    return private_key.decrypt(
        ciphertext_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ─────────────────────────────────────────────
# AES-GCM SECTION
# ─────────────────────────────────────────────

def aes_encrypt(key_bytes, plaintext_str):
    """
    Encrypt a plaintext string with AES-256-GCM.

    Args:
        key_bytes:     32-byte raw AES key
        plaintext_str: message to encrypt

    Returns dict with base64-encoded 'nonce' and 'ciphertext'.
    """
    nonce = os.urandom(12)                          # 96-bit nonce (GCM standard)
    aesgcm = AESGCM(key_bytes)
    ct = aesgcm.encrypt(nonce, plaintext_str.encode(), None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
    }


def aes_decrypt(key_bytes, nonce_b64, ciphertext_b64):
    """
    Decrypt an AES-256-GCM ciphertext.

    Returns the original plaintext string, or raises on authentication failure.
    """
    nonce = base64.b64decode(nonce_b64)
    ct    = base64.b64decode(ciphertext_b64)
    aesgcm = AESGCM(key_bytes)
    return aesgcm.decrypt(nonce, ct, None).decode()


# ─────────────────────────────────────────────
# FINGERPRINT SECTION
# ─────────────────────────────────────────────

def key_fingerprint(public_key):
    """
    Compute a human-readable SHA-256 fingerprint of an RSA public key.

    Serializes the key to DER, hashes with SHA-256, and formats as
    4 groups of 8 hex characters (similar to WhatsApp / Signal safety numbers).

    Returns a string like: 'a1b2c3d4 e5f6a7b8 c9d0e1f2 a3b4c5d6'.
    """
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).hexdigest()   # 64 hex chars
    # Split into 8 groups of 8 and take the first 4 for a readable fingerprint
    groups = [digest[i:i+8] for i in range(0, 32, 8)]
    return " ".join(groups)
