"""TIBET token schemas for transfer_out / transfer_in / tombstone.

Per Phase 0 spec (phase-0-tombstone-transfer-pair-spec.md):
- transfer_out: sender chain entry
- transfer_in: receiver chain entry (with generation inheritance)
- tombstone_token: optional cryptographic deactivation
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .crypto import IdentityKey, sha256_hex, verify_signature
from .handshake import tpid_str


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _canonical_json(obj: dict) -> bytes:
    """Deterministic JSON for signature input."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class TransferOutToken:
    actor_aint: str
    actor_pubkey: bytes
    receiver_aint: str
    receiver_fp: bytes
    payload_type: str
    payload_summary: dict
    transfer_pair_id: bytes
    generation: int
    prev_token_id: str | None = None
    tunnel_method: str = "wifi_direct_aes256gcm"
    session_ephemeral_pubkey: bytes | None = None
    consent_ts: str | None = None
    token_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self, signer: IdentityKey) -> dict:
        body = {
            "token_type": "transfer_out",
            "token_id": self.token_id,
            "actor": self.actor_aint,
            "actor_pubkey": self.actor_pubkey.hex(),
            "created_at": _now_iso(),
            "prev_token_id": self.prev_token_id,
            "generation": self.generation,
            "eraan": {
                "transfer_pair_id": tpid_str(self.transfer_pair_id),
                "receiver_aint": self.receiver_aint,
                "receiver_fp": self.receiver_fp.hex(),
                "payload_type": self.payload_type,
                "payload_summary": self.payload_summary,
                "tunnel_method": self.tunnel_method,
                "session_ephemeral_pubkey": (
                    self.session_ephemeral_pubkey.hex()
                    if self.session_ephemeral_pubkey else None
                ),
                "consent_ts": self.consent_ts or _now_iso(),
                "device_fp_self": sha256_hex(self.actor_pubkey),
            },
            "erachter": "device_state_handoff",
            "erin": "TIBET Drop transfer initiated — outbound",
            "eromheen": "Mutual causal anchor with receiver chain",
            "state": "transferred_out",
        }
        canonical = _canonical_json(
            {k: v for k, v in body.items() if k != "sig"}
        )
        body["sig"] = signer.sign(canonical).hex()
        return body


@dataclass
class TransferInToken:
    actor_aint: str
    actor_pubkey: bytes
    sender_aint: str
    sender_fp: bytes
    payload_type: str
    payload_received: dict
    transfer_pair_id: bytes
    sender_generation: int
    local_generation: int
    sender_transfer_out_token_id: str
    prev_token_id: str | None = None
    tunnel_method: str = "wifi_direct_aes256gcm"
    session_ephemeral_pubkey: bytes | None = None
    consent_ts: str | None = None
    token_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def generation(self) -> int:
        """Per Phase 0 spec §1.4 (Lamport-style):
        max(local_generation, sender_generation) + 1
        """
        return max(self.local_generation, self.sender_generation) + 1

    def to_dict(self, signer: IdentityKey) -> dict:
        body = {
            "token_type": "transfer_in",
            "token_id": self.token_id,
            "actor": self.actor_aint,
            "actor_pubkey": self.actor_pubkey.hex(),
            "created_at": _now_iso(),
            "prev_token_id": self.prev_token_id,
            "generation": self.generation,
            "eraan": {
                "transfer_pair_id": tpid_str(self.transfer_pair_id),
                "sender_aint": self.sender_aint,
                "sender_fp": self.sender_fp.hex(),
                "payload_type": self.payload_type,
                "payload_received": self.payload_received,
                "tunnel_method": self.tunnel_method,
                "session_ephemeral_pubkey": (
                    self.session_ephemeral_pubkey.hex()
                    if self.session_ephemeral_pubkey else None
                ),
                "consent_ts": self.consent_ts or _now_iso(),
                "device_fp_self": sha256_hex(self.actor_pubkey),
                "sender_chain_ref": {
                    "transfer_out_token_id": self.sender_transfer_out_token_id,
                    "sender_generation": self.sender_generation,
                },
            },
            "erachter": "device_state_handoff",
            "erin": "TIBET Drop transfer received — inbound",
            "eromheen": "Mutual causal anchor with sender chain",
            "state": "received",
        }
        canonical = _canonical_json(
            {k: v for k, v in body.items() if k != "sig"}
        )
        body["sig"] = signer.sign(canonical).hex()
        return body


@dataclass
class TombstoneToken:
    actor_aint: str
    actor_pubkey: bytes
    transfer_out_ref: str
    successor_aint: str
    successor_fp: bytes
    invalidation_scope: str = "all_subsequent_state"
    recovery_policy: str = "destroyed"
    deactivation_method: str = "post_airdrop_handoff"
    generation: int = 0
    prev_token_id: str | None = None
    token_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self, signer: IdentityKey) -> dict:
        body = {
            "token_type": "tombstone_token",
            "token_id": self.token_id,
            "actor": self.actor_aint,
            "actor_pubkey": self.actor_pubkey.hex(),
            "created_at": _now_iso(),
            "prev_token_id": self.prev_token_id,
            "generation": self.generation,
            "eraan": {
                "deactivation_method": self.deactivation_method,
                "transfer_out_ref": self.transfer_out_ref,
                "successor_device": (
                    f"{self.successor_aint}:{self.successor_fp.hex()}"
                ),
                "valid_until": _now_iso(),
                "invalidation_scope": self.invalidation_scope,
                "recovery_policy": self.recovery_policy,
            },
            "erachter": "device_lifecycle_termination",
            "erin": "Cryptographic deactivation attestation",
            "eromheen": "State handoff complete; subsequent claims invalid",
            "state": "terminal",
        }
        canonical = _canonical_json(
            {k: v for k, v in body.items() if k != "sig"}
        )
        body["sig"] = signer.sign(canonical).hex()
        return body


def verify_token(token: dict) -> tuple[bool, str | None]:
    """Verify a token's Ed25519 signature."""
    sig_hex = token.get("sig")
    pubkey_hex = token.get("actor_pubkey")
    if not sig_hex or not pubkey_hex:
        return False, "Missing sig or actor_pubkey"
    try:
        sig = bytes.fromhex(sig_hex)
        pubkey = bytes.fromhex(pubkey_hex)
    except ValueError as e:
        return False, f"Invalid hex: {e}"

    body_no_sig = {k: v for k, v in token.items() if k != "sig"}
    canonical = _canonical_json(body_no_sig)
    if not verify_signature(pubkey, canonical, sig):
        return False, "Signature verification failed"
    return True, None
