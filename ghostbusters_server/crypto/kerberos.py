"""Quazal Kerberos crypto for Ghostbusters PS3 (Sony NP variant).

Canonical Quazal key-derivation formula:

    K_user(pid) = MD5_iter(KDF_PASSWORD, 65000 + (pid % 1024))

K_user is the symmetric key the auth service uses to encrypt the outer
kerb_cipher returned in Login / RequestTicket responses. The same formula
applies to service PIDs (1 = secure service, 2 = auth service), so the
auth service can encrypt the inner ticket with K_user(target_pid) and the
target service can decrypt it later with the same derivation.

Wire layout:

    kerb_cipher = RC4(K_client).enc(plain) + HMAC_MD5(K_client, ciphertext)
    plain       = session_key(16) | server_pid(u32 LE) | ticket_len(u32 LE) | ticket
    ticket      = RC4(K_target).enc(inner_plain) + HMAC_MD5(K_target, ciphertext)
    inner_plain = source_pid(u32 LE) | session_key(16) | padding

For mutual auth on the secure CONNECT exchange:

    reqd        = RC4(session_key).enc([pid|cid|check] u32 LE x3) + HMAC_MD5
    connect_ack = [4|check+1] u32 LE x2                              # plaintext

The CONNECT+ACK token is NOT RC4'd with session_key — proof that the server
knew the session_key is the fact that it parsed reqd correctly and extracted
check_value, not any cipher property of the response. The standard PRUDP
obfuscation (RC4 with the configured RC4_KEY) still wraps the bytes on the wire.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

from Crypto.Cipher import ARC4

from .. import config


KDF_PASSWORD = config.KDF_PASSWORD
KDF_BASE = 65000
KDF_MAX  = 1024

SESSION_KEY_SIZE = 16
HMAC_TAG_SIZE    = 16

# Total kerb_cipher sizes on the wire.
LOGIN_CIPHER_SIZE          = 88
REQUEST_TICKET_CIPHER_SIZE = 98


def derive_user_key(pid: int) -> bytes:
    """16-byte master key for a given PID. ~8ms on a modern CPU."""
    state = KDF_PASSWORD
    iter_count = KDF_BASE + (pid % KDF_MAX)
    for _ in range(iter_count):
        state = hashlib.md5(state).digest()
    return state


# --- encrypt-then-MAC envelope ----------------------------------------------

def encrypt_then_mac(key: bytes, plaintext: bytes) -> bytes:
    ct = ARC4.new(key).encrypt(plaintext)
    tag = hmac.new(key, ct, hashlib.md5).digest()
    return ct + tag


def decrypt_and_verify(key: bytes, ct_with_tag: bytes) -> bytes:
    if len(ct_with_tag) < HMAC_TAG_SIZE:
        raise ValueError(f"ciphertext too short for HMAC tag: {len(ct_with_tag)}B")
    ct, tag = ct_with_tag[:-HMAC_TAG_SIZE], ct_with_tag[-HMAC_TAG_SIZE:]
    expected = hmac.new(key, ct, hashlib.md5).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("HMAC verification failed")
    return ARC4.new(key).decrypt(ct)


def rc4_encrypt(key: bytes, plaintext: bytes) -> bytes:
    return ARC4.new(key).encrypt(plaintext)


def rc4_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    return ARC4.new(key).decrypt(ciphertext)


# --- kerb_cipher construction (auth service side) ---------------------------

def _build_inner_ticket(target_pid: int, source_pid: int,
                        session_key: bytes, total_size: int) -> bytes:
    assert len(session_key) == SESSION_KEY_SIZE
    plain_size = total_size - HMAC_TAG_SIZE
    pad_size = plain_size - 4 - SESSION_KEY_SIZE
    if pad_size < 0:
        raise ValueError(f"total_size {total_size} too small for ticket header")
    plain = source_pid.to_bytes(4, "little") + session_key + os.urandom(pad_size)
    return encrypt_then_mac(derive_user_key(target_pid), plain)


def _build_kerb_cipher(client_pid: int, target_pid: int,
                       total_size: int) -> tuple[bytes, bytes]:
    session_key = os.urandom(SESSION_KEY_SIZE)
    ticket_len = total_size - HMAC_TAG_SIZE - SESSION_KEY_SIZE - 4 - 4
    ticket = _build_inner_ticket(target_pid, client_pid, session_key, ticket_len)
    plain = (
        session_key
        + target_pid.to_bytes(4, "little")
        + ticket_len.to_bytes(4, "little")
        + ticket
    )
    return encrypt_then_mac(derive_user_key(client_pid), plain), session_key


def build_login_cipher(client_pid: int, secure_pid: int) -> tuple[bytes, bytes]:
    """88-byte kerb_cipher for a Login response. Returns (cipher, session_key)."""
    return _build_kerb_cipher(client_pid, secure_pid, LOGIN_CIPHER_SIZE)


def build_request_ticket_cipher(client_pid: int, target_pid: int) -> tuple[bytes, bytes]:
    """98-byte kerb_cipher for a RequestTicket response."""
    return _build_kerb_cipher(client_pid, target_pid, REQUEST_TICKET_CIPHER_SIZE)


# --- secure CONNECT mutual auth (secure service side) -----------------------

def extract_session_key_from_ticket(ticket: bytes, secure_pid: int) -> bytes:
    """Decrypt a forwarded ticket with K_user(secure_pid), return session_key."""
    return extract_ticket_payload(ticket, secure_pid)[0]


def extract_ticket_payload(ticket: bytes, secure_pid: int) -> tuple[bytes, int]:
    """Decrypt a forwarded ticket with K_user(secure_pid).
    Returns (session_key, source_pid) — source_pid is the user's PID that
    `build_inner_ticket` embedded at offset 0 of the inner plaintext.
    """
    plain = decrypt_and_verify(derive_user_key(secure_pid), ticket)
    if len(plain) < 4 + SESSION_KEY_SIZE:
        raise ValueError(f"inner ticket plaintext too short: {len(plain)}B")
    source_pid = int.from_bytes(plain[:4], "little")
    session_key = plain[4:4 + SESSION_KEY_SIZE]
    return session_key, source_pid


def parse_reqd(reqd: bytes, session_key: bytes) -> tuple[int, int, int]:
    """Decrypt+verify the 28B reqd from a secure CONNECT, return (pid, cid, check_value)."""
    plain = decrypt_and_verify(session_key, reqd)
    if len(plain) < 12:
        raise ValueError(f"reqd plaintext too short: {len(plain)}B")
    return struct.unpack("<III", plain[:12])


def build_connect_ack_token(session_key: bytes, check_value: int) -> bytes:
    """8-byte mutual-auth response = plaintext [u32 LE 4][u32 LE check_value+1].

    `session_key` is unused (kept in the signature for symmetry / future use)
    — this Quazal Rendez-Vous variant doesn't RC4-wrap the token. The server
    proves it knows the session_key by having decrypted reqd, not by encrypting
    the reply. Example: `04 00 00 00 87 08 45 e2` is the token for
    check_value=0xe2450886 (check+1=0xe2450887).
    """
    del session_key  # intentionally unused
    return struct.pack("<II", 4, (check_value + 1) & 0xFFFFFFFF)
