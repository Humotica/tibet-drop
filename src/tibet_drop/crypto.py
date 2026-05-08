"""Crypto primitives for TIBET TAT wire protocol.

Per Phase 0 spec (phase-0-upip-seed-and-ecdh.md):
- Ed25519 for identity signing
- X25519 ephemeral for ECDH
- HKDF-SHA256 for key derivation
- AES-256-GCM for tunnel encryption
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand


INFO_LABEL = b"AInternet-Airdrop-Tunnel-v1"


# ─── Identity (Ed25519) ────────────────────────────────────────────

@dataclass
class IdentityKey:
    """Long-lived Ed25519 identity keypair."""
    priv: ed25519.Ed25519PrivateKey
    pub: ed25519.Ed25519PublicKey

    @classmethod
    def generate(cls) -> "IdentityKey":
        priv = ed25519.Ed25519PrivateKey.generate()
        return cls(priv=priv, pub=priv.public_key())

    def sign(self, data: bytes) -> bytes:
        return self.priv.sign(data)

    def pub_bytes(self) -> bytes:
        return self.pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def fingerprint(self) -> bytes:
        return hashlib.sha256(self.pub_bytes()).digest()


def verify_signature(pub_bytes: bytes, data: bytes, sig: bytes) -> bool:
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig, data)
        return True
    except Exception:
        return False


# ─── Ephemeral (X25519) ─────────────────────────────────────────────

@dataclass
class EphemeralKey:
    """Short-lived X25519 keypair for one airdrop's ECDH."""
    priv: x25519.X25519PrivateKey
    pub: x25519.X25519PublicKey

    @classmethod
    def generate(cls) -> "EphemeralKey":
        priv = x25519.X25519PrivateKey.generate()
        return cls(priv=priv, pub=priv.public_key())

    def pub_bytes(self) -> bytes:
        return self.pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


def derive_tunnel_keys(
    my_eph: EphemeralKey,
    peer_eph_pub_bytes: bytes,
    tpid: bytes,
) -> tuple[bytes, bytes]:
    """ECDH + HKDF per Phase 0 spec §3.

    Returns (tunnel_key=32B, nonce_prefix=8B).
    """
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_eph_pub_bytes)
    shared_secret = my_eph.priv.exchange(peer_pub)

    tunnel_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=tpid,
        info=INFO_LABEL,
    ).derive(shared_secret)

    nonce_prefix = HKDF(
        algorithm=hashes.SHA256(),
        length=8,
        salt=tpid,
        info=INFO_LABEL + b"\x01",
    ).derive(shared_secret)

    return tunnel_key, nonce_prefix


# ─── AES-256-GCM frame encryption ──────────────────────────────────

def encrypt_chunk(
    tunnel_key: bytes,
    nonce_prefix: bytes,
    chunk_index: int,
    plaintext: bytes,
    aad: bytes,
) -> bytes:
    """Per Phase 0 spec §3.4 (NORMATIVE):
    nonce = nonce_prefix(8) || u32_be(chunk_index)(4) = 12 bytes.
    """
    nonce = nonce_prefix + struct.pack(">I", chunk_index)
    aes = AESGCM(tunnel_key)
    return aes.encrypt(nonce, plaintext, aad)


def decrypt_chunk(
    tunnel_key: bytes,
    nonce_prefix: bytes,
    chunk_index: int,
    ciphertext: bytes,
    aad: bytes,
) -> bytes:
    nonce = nonce_prefix + struct.pack(">I", chunk_index)
    aes = AESGCM(tunnel_key)
    return aes.decrypt(nonce, ciphertext, aad)


# ─── Hashing helpers ────────────────────────────────────────────────

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
