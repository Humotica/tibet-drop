"""UPIP-seed handshake encoding/decoding for TIBET TAT.

Per Phase 0 spec (phase-0-upip-seed-and-ecdh.md §1):
- CBOR-encoded, ~250 bytes, ≤512 bytes hard limit
- Ed25519-signed
- Carries pubkeys + tpid + intent + ephemeral X25519 pub
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

import cbor2

from .crypto import IdentityKey, verify_signature


SEED_KIND_HANDSHAKE = "airdrop_handshake"
SEED_KIND_CONSENT = "airdrop_consent"
MAX_SEED_BYTES = 512


@dataclass
class SendSeed:
    """Sender → receiver UPIP-seed."""
    aint: str
    pk_from: bytes
    epk_from: bytes
    tpid: bytes
    intent: dict
    tunnel: str = "wifi_direct"
    ts_ms: int | None = None
    sig: bytes | None = None

    def to_canonical_no_sig(self) -> dict:
        return {
            "v": 1,
            "kind": SEED_KIND_HANDSHAKE,
            "from": self.aint,
            "fp_from": self.fp_from(),
            "pk_from": self.pk_from,
            "epk_from": self.epk_from,
            "tpid": self.tpid,
            "intent": self.intent,
            "tunnel": self.tunnel,
            "ts": self.ts_ms or int(time.time() * 1000),
        }

    def fp_from(self) -> bytes:
        from .crypto import sha256
        return sha256(self.pk_from)

    def encode(self, signer: IdentityKey) -> bytes:
        body = self.to_canonical_no_sig()
        canonical = cbor2.dumps(body, canonical=True)
        self.sig = signer.sign(canonical)
        body["sig"] = self.sig
        return cbor2.dumps(body, canonical=True)


@dataclass
class RecvSeed:
    """Receiver → sender consent UPIP-seed."""
    aint: str
    pk_from: bytes
    epk_from: bytes
    tpid: bytes
    consent: str  # "accept" | "reject" | "request_more"
    ts_ms: int | None = None
    sig: bytes | None = None

    def to_canonical_no_sig(self) -> dict:
        from .crypto import sha256
        return {
            "v": 1,
            "kind": SEED_KIND_CONSENT,
            "from": self.aint,
            "fp_from": sha256(self.pk_from),
            "pk_from": self.pk_from,
            "epk_from": self.epk_from,
            "tpid": self.tpid,
            "consent": self.consent,
            "ts": self.ts_ms or int(time.time() * 1000),
        }

    def encode(self, signer: IdentityKey) -> bytes:
        body = self.to_canonical_no_sig()
        canonical = cbor2.dumps(body, canonical=True)
        self.sig = signer.sign(canonical)
        body["sig"] = self.sig
        return cbor2.dumps(body, canonical=True)


def decode_seed(blob: bytes) -> dict:
    """Decode a CBOR-encoded UPIP-seed into a raw dict."""
    return cbor2.loads(blob)


def verify_seed(blob: bytes) -> tuple[bool, dict, str | None]:
    """Verify a seed's Ed25519 signature.

    Returns (valid, decoded_dict, error_or_None).
    """
    if len(blob) > MAX_SEED_BYTES:
        return False, {}, f"Seed exceeds hard limit: {len(blob)} > {MAX_SEED_BYTES} bytes"

    try:
        body = cbor2.loads(blob)
    except Exception as e:
        return False, {}, f"CBOR decode failed: {e}"

    kind = body.get("kind")
    if kind not in {SEED_KIND_HANDSHAKE, SEED_KIND_CONSENT}:
        return False, body, f"Unsupported kind: {kind!r}"

    sig = body.get("sig")
    if not sig:
        return False, body, "Missing signature"

    pk = body.get("pk_from")
    if not pk:
        return False, body, "Missing pk_from"

    tpid = body.get("tpid")
    if not isinstance(tpid, (bytes, bytearray)) or len(tpid) != 16:
        return False, body, "Missing or invalid tpid"

    body_no_sig = {k: v for k, v in body.items() if k != "sig"}
    canonical = cbor2.dumps(body_no_sig, canonical=True)

    if not verify_signature(pk, canonical, sig):
        return False, body, "Signature verification failed"

    return True, body, None


def new_tpid() -> bytes:
    """Generate transfer_pair_id (UUID v7-style, time-ordered)."""
    # Python's uuid module has no v7 yet (3.12+ may), so synthesize.
    # 48-bit ms timestamp + 80-bit random for time-ordering.
    import os
    ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand = os.urandom(10)
    raw = ms.to_bytes(6, "big") + rand
    # Set version 7 + variant bits per RFC 9562
    raw_bytes = bytearray(raw)
    raw_bytes[6] = (raw_bytes[6] & 0x0F) | 0x70
    raw_bytes[8] = (raw_bytes[8] & 0x3F) | 0x80
    return bytes(raw_bytes)


def tpid_str(tpid: bytes) -> str:
    """Format a 16-byte tpid as standard UUID string."""
    return str(uuid.UUID(bytes=tpid))
