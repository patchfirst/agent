"""End-to-end encryption of server names (UUID → name) with a view key.

The fleet owner holds the view key (in .credentials, the agent config, or the dashboard link fragment)
and never sends it to the server. The server stores ciphertext; the browser decrypts it with WebCrypto (AES-GCM).
Format: "v1.<nonce b64url>.<ciphertext b64url>", AAD = "psr-labels/<fleet>/<host>".
In v1, dictionary keys are hidden from the service: validate UUIDs at the sealing boundary.
Paths, programs, and their HMAC labels are forbidden in this dictionary even when encrypted.
"""
import base64
import json
import os
import secrets
import uuid

MAX_NAME = 255
# One {server UUID: name} entry, every character JSON-escaped, is the largest dictionary.
MAX_PLAINTEXT = len(json.dumps({str(uuid.UUID(int=0)): "\x00" * MAX_NAME}))


def b64e(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64d(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def new_key():
    return b64e(secrets.token_bytes(32))


def aesgcm(key):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return None
    return AESGCM(b64d(key))


def available():
    return aesgcm(new_key()) is not None


def aad(fleet, host):
    return ("psr-labels/%s/%s" % (fleet, host)).encode()


def seal(key, fleet, host, value):
    if isinstance(value, dict):
        for identifier, name in value.items():
            try:
                valid_uuid = isinstance(identifier, str) and str(uuid.UUID(identifier)) == identifier
            except (ValueError, AttributeError):
                valid_uuid = False
            if not valid_uuid or not isinstance(name, str):
                raise ValueError("the name dictionary accepts only server UUIDs and string names")
    elif host != 'verifier' or value != 'psr-names-ok':
        raise ValueError("only server names or the name password check can be sealed")
    box = aesgcm(key)
    if box is None:
        raise RuntimeError("python3-cryptography is missing; cannot encrypt the name dictionary, the dashboard will show UUIDs")
    plaintext = json.dumps(value, ensure_ascii=False).encode()
    if len(plaintext) > MAX_PLAINTEXT:
        raise ValueError("the name dictionary exceeds one server name")
    nonce = os.urandom(12)
    return "v1.%s.%s" % (b64e(nonce), b64e(box.encrypt(nonce, plaintext, aad(fleet, host))))
