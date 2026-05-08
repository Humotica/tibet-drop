"""Stateful verification helpers for TIBET Drop.

These helpers sit one layer above pure signature/crypto verification:
- persistent replay prevention for transfer_pair_id values
- asymmetry detection between transfer_out and transfer_in
- tombstone-aware rejection of post-terminal activity
- chunk-index continuity checks for streamed transfers
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .tokens import verify_token


def _parse_iso_utc(value: str | None) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=UTC)
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized).astimezone(UTC)


def _transfer_pair_id(token: dict) -> str | None:
    eraan = token.get("eraan", {})
    tpid = eraan.get("transfer_pair_id")
    return str(tpid) if tpid else None


class ReplayStore:
    """Persistent seen_tpid registry backed by a JSON file."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text(json.dumps({"seen_tpids": []}, indent=2), encoding="utf-8")

    def _load(self) -> set[str]:
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        return set(payload.get("seen_tpids", []))

    def _save(self, seen: set[str]) -> None:
        self.path.write_text(
            json.dumps({"seen_tpids": sorted(seen)}, indent=2),
            encoding="utf-8",
        )

    def contains(self, tpid: str) -> bool:
        return tpid in self._load()

    def remember(self, tpid: str) -> None:
        seen = self._load()
        seen.add(tpid)
        self._save(seen)


@dataclass
class ChunkSequenceGate:
    """Stateful guard for sequential chunk indexes."""

    expected_next: int = 0

    def accept(self, chunk_index: int) -> tuple[bool, str | None]:
        if chunk_index != self.expected_next:
            if chunk_index < self.expected_next:
                return False, f"chunk index decreased: expected {self.expected_next} got {chunk_index}"
            return False, f"chunk index gap: expected {self.expected_next} got {chunk_index}"
        self.expected_next += 1
        return True, None


@dataclass
class VerificationState:
    """In-memory state for transfer-pair and tombstone checks."""

    transfer_out_by_tpid: dict[str, dict] = field(default_factory=dict)
    tombstone_by_actor_pubkey: dict[str, dict] = field(default_factory=dict)

    def register_transfer_out(self, token: dict) -> None:
        tpid = _transfer_pair_id(token)
        if tpid:
            self.transfer_out_by_tpid[tpid] = token

    def register_tombstone(self, token: dict) -> None:
        actor_pubkey = token.get("actor_pubkey")
        if actor_pubkey:
            self.tombstone_by_actor_pubkey[str(actor_pubkey)] = token


def verify_transfer_out_token(
    token: dict,
    replay_store: ReplayStore | None = None,
    state: VerificationState | None = None,
) -> tuple[bool, str | None]:
    valid, err = verify_token(token)
    if not valid:
        return False, err
    if token.get("token_type") != "transfer_out":
        return False, "Expected transfer_out token"

    tpid = _transfer_pair_id(token)
    if not tpid:
        return False, "Missing transfer_pair_id"
    if replay_store and replay_store.contains(tpid):
        return False, f"Replay detected for transfer_pair_id {tpid}"

    if replay_store:
        replay_store.remember(tpid)
    if state:
        state.register_transfer_out(token)
    return True, None


def verify_transfer_in_token(
    token: dict,
    *,
    matching_transfer_out: dict | None = None,
    state: VerificationState | None = None,
) -> tuple[bool, str | None]:
    valid, err = verify_token(token)
    if not valid:
        return False, err
    if token.get("token_type") != "transfer_in":
        return False, "Expected transfer_in token"

    tpid = _transfer_pair_id(token)
    if not tpid:
        return False, "Missing transfer_pair_id"

    out_token = matching_transfer_out
    if out_token is None and state is not None:
        out_token = state.transfer_out_by_tpid.get(tpid)
    if out_token is None:
        return False, f"Asymmetry detected: no matching transfer_out for {tpid}"

    out_tpid = _transfer_pair_id(out_token)
    if out_tpid != tpid:
        return False, "transfer_in / transfer_out tpid mismatch"

    sender_ref = token.get("eraan", {}).get("sender_chain_ref", {})
    if sender_ref.get("transfer_out_token_id") != out_token.get("token_id"):
        return False, "sender_chain_ref.transfer_out_token_id mismatch"
    return True, None


def verify_tombstone_token(
    token: dict,
    state: VerificationState | None = None,
) -> tuple[bool, str | None]:
    valid, err = verify_token(token)
    if not valid:
        return False, err
    if token.get("token_type") != "tombstone_token":
        return False, "Expected tombstone_token"
    if state:
        state.register_tombstone(token)
    return True, None


def reject_if_post_tombstone(
    token: dict,
    state: VerificationState,
) -> tuple[bool, str | None]:
    if token.get("token_type") == "tombstone_token":
        return True, None

    actor_pubkey = str(token.get("actor_pubkey", ""))
    tomb = state.tombstone_by_actor_pubkey.get(actor_pubkey)
    if not tomb:
        return True, None

    tomb_created = _parse_iso_utc(tomb.get("created_at"))
    token_created = _parse_iso_utc(token.get("created_at"))
    if token_created > tomb_created:
        recovery_policy = tomb.get("eraan", {}).get("recovery_policy", "unknown")
        return False, (
            "Post-tombstone token rejected "
            f"(recovery_policy={recovery_policy})"
        )
    return True, None
